use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(subcommand)]
    Auth(AuthCommand),
    #[command(subcommand)]
    Company(CompanyCommand),
    #[command(subcommand)]
    Repo(RepoCommand),
    Status {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(
            long = "as-of",
            help = "Explicit RFC 3339 UTC millisecond reducer instant; defaults to the recorded proof clock"
        )]
        as_of: Option<String>,
    },
    Doctor {
        #[arg(long, value_enum)]
        host: Option<Host>,
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Compact the Personal ledgers by identity and bring their index up to
    /// date, off the hook path. SessionEnd starts one when it is due.
    Dream {
        /// Dream even when one finished within the day.
        #[arg(long)]
        force: bool,
    },
    Ingest {
        source_kind: String,
        source: PathBuf,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        checkpoint: Option<String>,
    },
    Classifier {
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        model: Option<String>,
        /// The processors the caller authorizes; defaults to the configured
        /// `classifier.processor_scope`, else `local`.
        #[arg(long = "processor-scope")]
        processor_scope: Option<String>,
    },
    #[command(subcommand)]
    Corpus(CorpusCommand),
    Fsck {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        full: bool,
        #[arg(long = "as-of")]
        as_of: Option<String>,
    },
    Explain {
        logical_key: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        decision: String,
        #[arg(long = "as-of")]
        as_of: Option<String>,
        #[arg(long)]
        authority_cursor: Option<u64>,
    },
    /// Answer the principal's own question from the Personal store's Kindex
    /// (`[personal] kindex_executable`). Runs only where the Personal root is
    /// held; the answer goes to this terminal and nowhere else.
    /// Answers the question read from standard input (never the command line,
    /// where the process list would show it) from the Personal Kindex. Only in
    /// a build with the test-only `personal-recall` feature.
    #[cfg(feature = "personal-recall")]
    Recall {
        /// Today's date for the answer ("now", "ago"); defaults to the current date.
        #[arg(long = "as-of")]
        as_of: Option<String>,
    },
    Project {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        task: String,
        #[arg(long)]
        decision: String,
        #[arg(long = "working-set", value_delimiter = ',')]
        working_set: Vec<String>,
        /// Other certified repositories whose Codebase stores are read as
        /// evidence alongside this repository's own (repeatable). A corpus
        /// repository holding tickets, pull requests, threads and documents
        /// is evidence for every service, not only for itself.
        #[arg(long = "evidence-repo")]
        evidence_repos: Vec<PathBuf>,
        #[arg(long = "as-of")]
        as_of: Option<String>,
    },
    #[command(subcommand)]
    Session(SessionCommand),
    #[command(subcommand)]
    Questions(QuestionCommand),
    #[command(subcommand)]
    Hooks(HookCommand),
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    Login,
}

#[derive(Debug, Subcommand)]
pub enum CompanyCommand {
    Init {
        #[arg(long)]
        config: PathBuf,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Summarize who has used the Company service, how, and how much:
    /// totals and breakdowns by principal, client, action and time window.
    Usage {
        #[arg(long)]
        config: PathBuf,
        /// Window start (inclusive), RFC 3339 UTC with millisecond precision.
        #[arg(long)]
        since: Option<String>,
        /// Window end (exclusive), RFC 3339 UTC with millisecond precision.
        #[arg(long)]
        until: Option<String>,
        #[arg(long, value_enum, default_value = "day")]
        bucket: UsageBucket,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UsageBucket {
    Day,
    Hour,
}

#[derive(Debug, Subcommand)]
pub enum RepoCommand {
    Issue {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        company: String,
    },
    Init {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
    },
    PublishManifest {
        #[arg(long)]
        repo: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    Rebuild {
        #[arg(long, value_enum)]
        store: Store,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "as-of")]
        as_of: Option<String>,
        #[arg(long)]
        reducer_version: Option<u64>,
        #[arg(long)]
        authority_cursor: Option<u64>,
    },
    /// Admit ingested observations into a store as signed facts.
    Admit {
        #[arg(long, value_enum)]
        store: Store,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        limit: Option<usize>,
        /// At most this many not-yet-classified documents are sent to the
        /// classifier this run; the rest wait for the next run.
        #[arg(long = "classify-limit")]
        classify_limit: Option<usize>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    Start {
        #[arg(long, value_enum)]
        host: Host,
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    Observe {
        session: String,
        #[arg(long)]
        event: PathBuf,
        /// Remove the event file afterwards (a prompt a host hook queued).
        #[arg(long, hide = true)]
        consume: bool,
    },
    Checkpoint {
        session: String,
    },
    End {
        session: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum QuestionCommand {
    List {
        #[arg(long)]
        owner: Option<String>,
    },
    Ask {
        question_id: String,
    },
    Answer {
        question_id: String,
        #[arg(long = "answer-file")]
        answer_file: PathBuf,
        #[arg(long = "key-file")]
        key_file: PathBuf,
    },
    Status {
        question_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookCommand {
    Plan { host: Host },
    Install { host: Host },
    Dispatch { host: Host, event: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Host {
    Codex,
    Claude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Store {
    Personal,
    Company,
    Codebase,
}
