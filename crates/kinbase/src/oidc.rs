use crate::error::ContractError;
use crate::http::{self, Scheme};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Config {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub session_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    refresh_token: String,
    id_token: String,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

pub fn validate_provider_url(url: &str) -> Result<(Scheme, String, u16, String), ContractError> {
    http::parse_url(url, !url.starts_with("http://"), true)
}

fn discovery(config: &Config) -> Result<Discovery, ContractError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        config.issuer.trim_end_matches('/')
    );
    let (scheme, host, port, path) = validate_provider_url(&url)?;
    let response = http::request(
        scheme,
        &host,
        port,
        "GET",
        &path,
        &[],
        &[],
        Duration::from_secs(20),
    )
    .map_err(provider)?;
    if !(200..300).contains(&response.status) || !response.body.is_object() {
        return Err(ContractError::unreachable("OIDC discovery failed"));
    }
    let discovered: Discovery = serde_json::from_value(response.body)
        .map_err(|_| ContractError::invariant("OIDC discovery document is incomplete"))?;
    if discovered.issuer != config.issuer {
        return Err(ContractError::invariant(
            "OIDC discovery issuer does not match oidc_issuer",
        ));
    }
    validate_provider_url(&discovered.authorization_endpoint)?;
    validate_provider_url(&discovered.token_endpoint)?;
    Ok(discovered)
}

fn provider(mut error: ContractError) -> ContractError {
    error.message = error.message.replacen("Company", "OIDC provider", 1);
    error
}

fn encode(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn token<'a>(
    config: &'a Config,
    url: &str,
    mut fields: Vec<(&'a str, &'a str)>,
) -> Result<Value, ContractError> {
    let (scheme, host, port, path) = validate_provider_url(url)?;
    fields.push(("client_id", &config.client_id));
    if let Some(secret) = &config.client_secret {
        fields.push(("client_secret", secret));
    }
    let body = form(&fields);
    let response = http::request(
        scheme,
        &host,
        port,
        "POST",
        &path,
        &[(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        )],
        body.as_bytes(),
        Duration::from_secs(20),
    )
    .map_err(provider)?;
    if (200..300).contains(&response.status) {
        return serde_json::from_slice(&response.raw)
            .map_err(|_| ContractError::unreachable("OIDC token response was not JSON"));
    }
    let code = response.body.get("error").and_then(Value::as_str);
    if response.status >= 500 || response.status == 429 || code == Some("temporarily_unavailable") {
        return Err(ContractError::unreachable("OIDC token endpoint failed"));
    }
    if code == Some("invalid_grant") {
        return Err(denied("OIDC session is no longer valid"));
    }
    let safe = code.filter(|code| {
        !code.is_empty()
            && code.len() <= 64
            && code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    });
    Err(ContractError::invariant(match safe {
        Some(code) => format!("OIDC provider returned OAuth error {code}"),
        None => "OIDC provider returned an invalid OAuth error".to_owned(),
    }))
}

fn denied(message: &str) -> ContractError {
    ContractError::refused(
        "AUTHORITY_SCOPE_DENIED",
        message,
        "Run `kinbase auth login`",
    )
}

fn claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

fn valid_for(token: &str, seconds: i64) -> bool {
    token.bytes().all(|byte| byte.is_ascii_graphic())
        && claims(token)
            .and_then(|claims| claims.get("exp").and_then(Value::as_f64))
            .is_some_and(|exp| {
                exp > chrono::Utc::now().timestamp_millis() as f64 / 1000.0 + seconds as f64
            })
}

fn response_id_token<'a>(response: &'a Value, operation: &str) -> Result<&'a str, ContractError> {
    let token = response
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or_else(|| denied(&format!("OIDC {operation} returned no usable ID token")))?;
    if claims(token)
        .and_then(|claims| claims.get("exp").and_then(Value::as_f64))
        .is_none()
    {
        return Err(denied(&format!(
            "OIDC {operation} returned no usable ID token"
        )));
    }
    if !valid_for(token, 0) {
        return Err(ContractError::unreachable(format!(
            "OIDC {operation} returned a stale or unusable ID token"
        )));
    }
    Ok(token)
}

fn load(path: &Path) -> Result<Session, ContractError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(denied("OIDC login is required"))
        }
        Err(error) => Err(ContractError::unreadable("OIDC session", &error)),
        Ok(_) => serde_json::from_str(&crate::crypto::read_private_text(path, "OIDC session")?)
            .map_err(|_| denied("stored OIDC session is unreadable")),
    }
}

fn save(config: &Config, session: &Session) -> Result<(), ContractError> {
    let bytes = serde_json::to_vec(session)
        .map_err(|_| ContractError::internal("OIDC session serialization failed"))?;
    crate::paths::write_atomic(&config.session_path, &bytes, 0o600, false).map(|_| ())
}

pub fn fresh_id_token(config: &Config) -> Result<String, ContractError> {
    let current = load(&config.session_path)?;
    if valid_for(&current.id_token, 300) {
        return Ok(current.id_token);
    }
    let _lock = crate::paths::lock_file(
        &config.session_path.with_file_name("oidc.lock"),
        "OIDC session lock",
    )?;
    let current = load(&config.session_path)?;
    if valid_for(&current.id_token, 300) {
        return Ok(current.id_token);
    }
    let discovered = discovery(config)?;
    let fields = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", current.refresh_token.as_str()),
    ];
    let result = token(config, &discovered.token_endpoint, fields).and_then(|response| {
        let id_token = response_id_token(&response, "refresh")?;
        let refresh_token = response
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .unwrap_or(&current.refresh_token);
        Ok(Session {
            refresh_token: refresh_token.to_owned(),
            id_token: id_token.to_owned(),
        })
    });
    if result
        .as_ref()
        .is_err_and(|error| error.code == "AUTHORITY_SCOPE_DENIED")
    {
        std::fs::remove_file(&config.session_path)
            .map_err(|error| ContractError::io("delete OIDC session", error))?;
    }
    let session = result?;
    save(config, &session)?;
    Ok(session.id_token)
}

pub fn login(config: &Config, json: bool) -> Result<String, ContractError> {
    let discovered = discovery(config)?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| ContractError::io("OIDC callback listener", error))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| ContractError::io("OIDC callback listener", error))?;
    let state = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let port = listener
        .local_addr()
        .map_err(|error| ContractError::io("OIDC callback listener", error))?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let offline = discovered
        .scopes_supported
        .iter()
        .any(|scope| scope == "offline_access");
    let scope = if offline {
        "openid email offline_access"
    } else {
        "openid email"
    };
    let query = form(&[
        ("response_type", "code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("scope", scope),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("access_type", "offline"),
        ("prompt", "consent"),
    ]);
    let joiner = if discovered.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!("{}{joiner}{query}", discovered.authorization_endpoint);
    if json {
        crate::output::diagnostic("login_url", serde_json::json!({"url": url}));
    } else {
        eprintln!("{url}");
    }
    let browser = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(browser)
        .arg(&url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let deadline = Instant::now() + Duration::from_secs(300);
    let code = loop {
        if Instant::now() >= deadline {
            return Err(denied("OIDC callback timed out after 5 minutes"));
        }
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(error) => return Err(ContractError::io("OIDC callback listener", error)),
        };
        stream
            .set_nonblocking(false)
            .and_then(|_| stream.set_read_timeout(Some(Duration::from_secs(2))))
            .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(2))))
            .map_err(|error| ContractError::io("OIDC callback timeout", error))?;
        let callback = stream
            .try_clone()
            .map_err(|error| ContractError::io("OIDC callback socket", error))?;
        let request = match http::within(Duration::from_secs(2), move || {
            http::read_request(&callback, 0)
        }) {
            Ok(Ok(request)) => request,
            _ => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
        };
        if request.route != "/callback" {
            let _ = http::respond(&mut stream, 404, &json!({"error":"not found"}));
            continue;
        }
        if request.query.get("state") != Some(&state) {
            let _ = http::respond(&mut stream, 400, &json!({"error":"invalid callback"}));
            continue;
        }
        let Some(code) = request
            .query
            .get("code")
            .filter(|code| !code.is_empty() && !request.query.contains_key("error"))
        else {
            let _ = http::respond(&mut stream, 400, &json!({"error":"login refused"}));
            return Err(denied("OIDC provider refused the login callback"));
        };
        let received = json!({"status":"sign-in received; return to the terminal"});
        let _ = http::respond(&mut stream, 200, &received);
        break code.clone();
    };
    let fields = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let response = token(config, &discovered.token_endpoint, fields)?;
    let id_token = response_id_token(&response, "login")?;
    let refresh_token = response
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| denied("OIDC login returned no refresh token"))?;
    let email = claims(id_token)
        .and_then(|claims| {
            claims
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .ok_or_else(|| denied("OIDC ID token has no email claim"))?;
    if email.chars().any(char::is_control) {
        return Err(denied("OIDC email claim contains control characters"));
    }
    let _lock = crate::paths::lock_file(
        &config.session_path.with_file_name("oidc.lock"),
        "OIDC session lock",
    )?;
    save(
        config,
        &Session {
            refresh_token: refresh_token.to_owned(),
            id_token: id_token.to_owned(),
        },
    )?;
    Ok(email)
}
