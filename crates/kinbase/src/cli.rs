use crate::Cli;
use crate::command_types::*;
use crate::error::ContractError;
use clap::Parser;
use clap::error::ErrorKind;
use std::path::{Path, PathBuf};

/// Parse the CLI while preserving the process contract.
///
/// Clap's default parser exits with its own usage code and prose. Kinbase
/// instead maps every refusal to the closed error taxonomy before any
/// launcher or repository state is touched.
pub fn parse_or_exit() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                    | ErrorKind::DisplayVersion
            ) {
                error.print().ok();
                std::process::exit(0);
            }

            let args: Vec<String> = std::env::args().skip(1).collect();
            let json = args.iter().any(|arg| arg == "--json");
            let contract_error = usage_error(&args, error.to_string());
            print_error(json, &contract_error);
            std::process::exit(contract_error.exit());
        }
    }
}

pub fn run(json: bool, command: Command) {
    let result = dispatch(json, command);
    if let Err(error) = result {
        print_error(json, &error);
        std::process::exit(error.exit());
    }
}

fn print_error(json: bool, error: &ContractError) {
    if json {
        let document = error
            .output_document
            .clone()
            .unwrap_or_else(|| crate::output::error_document(error));
        // R-15: the top-level error boundary owns JSON output.  stdout is
        // therefore never empty for a typed error, while stderr remains free
        // for optional JSON-line diagnostics.  Rich command envelopes may
        // contain non-record floats, so use the same renderer as output emit.
        let line = crate::output::single_line(&document);
        println!("{}", line);
        eprintln!("{}", line);
    } else {
        println!("{}: {}", error.code, error.message);
        println!("remediation: {}", error.remediation);
        println!("retryable: {}", error.retryable);
        println!("evidence_id: {}", error.evidence_id);
    }
}

/// Convert malformed invocations to the closed configuration contract.
fn usage_error(_args: &[String], _detail: String) -> ContractError {
    ContractError::invariant("malformed command line; no state was changed")
}

fn dispatch(json: bool, command: Command) -> Result<(), ContractError> {
    let launcher = crate::launcher::Launcher::load()?;
    match command {
        Command::Auth(AuthCommand::Login) => {
            let config = launcher
                .user
                .as_ref()
                .map_or(Ok(None), crate::config::UserConfig::oidc)?
                .ok_or_else(|| ContractError::invariant("OIDC is not configured"))?;
            let email = crate::oidc::login(&config, json)?;
            if json {
                crate::output::emit(&serde_json::json!({"signed_in_as": email}), true);
            } else {
                println!("signed in as {email}");
            }
        }
        Command::Company(CompanyCommand::Init { config }) => {
            crate::company::init(&config, json).map_err(internal)?;
        }
        Command::Company(CompanyCommand::Serve { config }) => {
            crate::company::serve(&config, json).map_err(internal)?;
        }
        Command::Company(CompanyCommand::Usage {
            config,
            since,
            until,
            bucket,
        }) => {
            let bucket = match bucket {
                UsageBucket::Day => crate::usage::Bucket::Day,
                UsageBucket::Hour => crate::usage::Bucket::Hour,
            };
            crate::company::usage(&config, since.as_deref(), until.as_deref(), bucket, json)
                .map_err(internal)?;
        }
        Command::Repo(RepoCommand::Issue { repo, company }) => {
            crate::repository::issue_certificate(launcher, &repo, &company, json)
                .map_err(internal)?;
        }
        Command::Repo(RepoCommand::Init { repo, certificate }) => {
            crate::repository::init(launcher, &repo, &certificate, json).map_err(internal)?;
        }
        Command::Repo(RepoCommand::PublishManifest { repo }) => {
            crate::repository::publish_manifest(launcher, &repo, json).map_err(internal)?;
        }
        Command::Status { repo, as_of } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(&launcher, &repo, as_of.as_deref())?;
            crate::repository::status(launcher, &repo, &as_of, json).map_err(internal)?;
        }
        Command::Dream { force } => {
            let repo = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let root = crate::store::ensure_store_root(crate::StoreKind::Personal, &repo)?;
            let result = crate::dream::dream(&root, force)?;
            if json {
                println!("{}", crate::json::canonical_text(&result));
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            }
        }
        Command::Doctor { host, repo } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::repository::doctor(
                launcher,
                &repo,
                host.map(|h| match h {
                    Host::Codex => "codex",
                    Host::Claude => "claude",
                }),
                json,
            )
            .map_err(internal)?;
        }
        Command::Ingest {
            source_kind,
            source,
            repo,
            checkpoint,
        } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            if crate::ingest::store_for_source(&source_kind) == crate::StoreKind::Codebase {
                let repository = crate::codebase::Repository::discover(&repo)?;
                let clock = crate::repository::recorded_clock(&launcher, &repository)?;
                crate::repository::ensure_authority_snapshot(&launcher, None, &clock)?;
            }
            crate::ingest::ingest(
                &launcher,
                &repo,
                &source_kind,
                &source,
                checkpoint.as_deref(),
                launcher.shared.classifier.as_ref(),
                json,
            )
            .map_err(internal)?;
        }
        Command::Classifier {
            provider,
            model,
            processor_scope,
        } => {
            let classifier = launcher.shared.classifier.as_ref();
            let configured = classifier
                .map(|classifier| classifier.model.clone())
                .unwrap_or_else(|| "deterministic".to_owned());
            let processor_scope = processor_scope
                .or_else(|| classifier.map(|classifier| classifier.processor_scope.clone()))
                .unwrap_or_else(|| "local".to_owned());
            crate::classifier::run(
                provider.as_deref(),
                model.as_deref(),
                &configured,
                &processor_scope,
                json,
            )?;
        }
        Command::Corpus(CorpusCommand::Rebuild {
            store,
            repo,
            as_of,
            reducer_version,
            authority_cursor,
        }) => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(&launcher, &repo, as_of.as_deref())?;
            crate::corpus::rebuild(
                &launcher,
                &repo,
                store_to_kind(store),
                &as_of,
                reducer_version,
                authority_cursor,
                json,
            )
            .map_err(internal)?;
        }
        Command::Corpus(CorpusCommand::Admit {
            store,
            repo,
            limit,
            classify_limit,
        }) => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::corpus::admit(
                &launcher,
                &repo,
                store_to_kind(store),
                limit,
                classify_limit,
                json,
            )
            .map_err(internal)?;
        }
        Command::Fsck { repo, full, as_of } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(&launcher, &repo, as_of.as_deref())?;
            crate::repository::fsck(launcher, &repo, full, &as_of, json).map_err(internal)?;
        }
        Command::Explain {
            logical_key,
            repo,
            decision,
            as_of,
            authority_cursor,
        } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(&launcher, &repo, as_of.as_deref())?;
            crate::corpus::explain(
                &launcher,
                &repo,
                &logical_key,
                &decision,
                &as_of,
                authority_cursor,
                json,
            )
            .map_err(internal)?;
        }
        Command::Project {
            repo,
            task,
            decision,
            working_set,
            evidence_repos,
            as_of,
        } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(&launcher, &repo, as_of.as_deref())?;
            crate::projector::run(
                &launcher,
                &repo,
                &task,
                &decision,
                &working_set,
                &evidence_repos,
                &as_of,
                json,
            )
            .map_err(internal)?;
        }
        #[cfg(feature = "personal-recall")]
        Command::Recall { as_of } => {
            let Some(user) = &launcher.user else {
                return Err(ContractError::refused(
                    "CONFIG_INVARIANT",
                    "recall needs a user config with a [personal] section",
                    "Create the launcher user config with [personal] data_root and kindex_executable.",
                ));
            };
            let Some(kindex) = &user.personal.kindex else {
                return Err(ContractError::refused(
                    "CONFIG_INVARIANT",
                    "recall needs the Personal store's Kindex ([personal] kindex_executable)",
                    "Configure kindex_executable and kindex_executable_sha256 under [personal].",
                ));
            };
            let question = read_question()?;
            // In a certified repository, and only when the configuration asks
            // for it (they go to the same processor as the question), the team
            // facts a read-only projection releases go with the question. The
            // projection raises no question to an owner and logs nothing, and a
            // withheld projection releases nothing.
            let team = if kindex.team_knowledge {
                let repo = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                resolve_as_of(&launcher, &repo, None)
                    .and_then(|projection_as_of| {
                        crate::projector::project_with(
                            &launcher,
                            &repo,
                            &question,
                            &question,
                            &[],
                            &[],
                            &projection_as_of,
                            crate::projector::Recording::ReadOnly,
                        )
                    })
                    .map(|projection| {
                        let statements = projection
                            .selected
                            .iter()
                            .map(|fact| (fact.fact_id.clone(), fact.statement.clone()))
                            .collect();
                        crate::personal_kindex::team_knowledge(&projection.result, &statements)
                    })
                    .unwrap_or_default()
            } else {
                crate::personal_kindex::TeamKnowledge {
                    report: serde_json::json!({"projection_state": "not_requested"}),
                    ..Default::default()
                }
            };
            let recalled = crate::personal_kindex::recall(
                kindex,
                &user.personal.data_root,
                &question,
                as_of.as_deref(),
                &team.items,
                &crate::time::now_rfc3339_millis(),
            )?;
            crate::output::emit(
                &serde_json::json!({
                    "status": "recalled",
                    "store": "personal",
                    "team_facts": team.facts,
                    "team": team.report,
                    "processors": recalled.processors,
                    "sent_sha256": recalled.sent_sha256,
                    "answer": recalled.answer
                }),
                json,
            );
        }
        Command::Session(SessionCommand::Start { host, repo }) => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::session::start(&repo, host_kind(host), json).map_err(internal)?;
        }
        Command::Session(SessionCommand::Observe {
            session,
            event,
            consume,
        }) => {
            // A queued host prompt is claimed first (one worker at a time)
            // and removed only once its observation is recorded.
            let claim = if consume {
                match crate::session::claim_pending(&event) {
                    Some(claim) => Some(claim),
                    None => return Ok(()),
                }
            } else {
                None
            };
            let event = claim.as_ref().map(|claim| claim.path()).unwrap_or(event);
            let observed = crate::session::observe(
                launcher.shared.classifier.as_ref(),
                launcher.shared.principal_id.as_str(),
                launcher.shared.host_instance_id.as_str(),
                &session,
                &event,
                json,
            );
            if let Some(claim) = claim {
                crate::session::finish_pending(claim, observed.as_ref().err());
            }
            observed.map_err(internal)?;
        }
        Command::Session(SessionCommand::Checkpoint { session }) => {
            crate::session::checkpoint(&session, json).map_err(internal)?;
        }
        Command::Session(SessionCommand::End { session }) => {
            crate::session::end(&session, json).map_err(internal)?;
        }
        Command::Session(SessionCommand::AbandonFanout {
            repo,
            destination,
            candidates,
            apply,
        }) => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::session::abandon_fanouts(&repo, &destination, &candidates, apply, json)
                .map_err(internal)?;
        }
        Command::Questions(command) => {
            crate::questions::dispatch(command, json).map_err(internal)?;
        }
        Command::Hooks(command) => {
            crate::hooks::dispatch(command, json).map_err(internal)?;
        }
    }
    Ok(())
}

fn internal(error: crate::error::ContractError) -> ContractError {
    error
}

/// The recall question, from standard input: a private question never goes on
/// a command line.
#[cfg(feature = "personal-recall")]
fn read_question() -> Result<String, ContractError> {
    use std::io::Read;
    const LIMIT: u64 = 64 * 1024;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ContractError::io("recall question", error))?;
    let refused = |message: &str| {
        ContractError::refused(
            "CONFIG_INVARIANT",
            message,
            "Pass the question on standard input, e.g. `printf %s 'your question' | kinbase recall`.",
        )
    };
    if bytes.len() as u64 > LIMIT {
        return Err(refused("the recall question is over 64 KiB"));
    }
    let question = String::from_utf8(bytes)
        .map_err(|_| refused("the recall question is not UTF-8"))?
        .trim()
        .to_owned();
    if question.is_empty() {
        return Err(refused("recall reads its question from standard input, and none was given"));
    }
    Ok(question)
}

fn resolve_as_of(
    launcher: &crate::launcher::Launcher,
    repo_path: &Path,
    explicit: Option<&str>,
) -> Result<crate::time::AsOf, ContractError> {
    if let Some(text) = explicit {
        return crate::time::AsOf::explicit(text).map_err(|message| {
            ContractError::new(
                "CONFIG_INVARIANT",
                message,
                "Pass --as-of as RFC 3339 UTC with millisecond precision, e.g. 2026-09-07T12:00:00.000Z.",
                false,
                crate::error::ExitCode::Refused,
            )
        });
    }

    let as_of_error = |message: String| {
        ContractError::new(
            "CONFIG_INVARIANT",
            message,
            "Run `kinbase repo init` once, or pass --as-of as RFC 3339 UTC with millisecond precision.",
            false,
            crate::error::ExitCode::Refused,
        )
    };
    let repo = crate::codebase::Repository::discover(repo_path)?;
    let local = repo.local_dir().join("proof-clock");
    let recorded = if let Ok(text) = std::fs::read_to_string(&local) {
        crate::time::AsOf::recorded(text.trim()).map_err(as_of_error)?
    } else {
        let store = launcher.private_store()?;
        let per_repo = match repo.uuid_hint() {
            Some(uuid) => store.meta(&format!("proof-clock:{uuid}"))?,
            None => None,
        };
        match per_repo.or(store.meta("proof-clock:default")?) {
            Some(value) => crate::time::AsOf::recorded(value.trim()).map_err(as_of_error)?,
            None => {
                return Err(as_of_error(
                    "no recorded proof clock is available; --as-of is required".to_owned(),
                ))
            }
        }
    };
    // The verified authority snapshot is recorded proof of a later instant.
    Ok(crate::repository::advance_as_of(launcher, &recorded))
}

fn store_to_kind(store: Store) -> crate::StoreKind {
    match store {
        Store::Personal => crate::StoreKind::Personal,
        Store::Company => crate::StoreKind::Company,
        Store::Codebase => crate::StoreKind::Codebase,
    }
}

fn host_kind(host: Host) -> crate::HostKind {
    match host {
        Host::Codex => crate::HostKind::Codex,
        Host::Claude => crate::HostKind::Claude,
    }
}
