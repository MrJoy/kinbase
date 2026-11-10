//! Minimal bounded HTTP/1.1 over TCP: request parsing with hard
//! limits, typed JSON responses, and a client with separate resolution and
//! connection budgets (architecture §9: 250 ms connect budget; §12: loopback
//! unless a managed deployment opts out).

use crate::error::ContractError;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// The longest request line accepted: a 2048-byte path plus method and
/// version.
pub const MAX_REQUEST_LINE_BYTES: usize = 2048 + 64;
pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_ERROR_BODY_BYTES: usize = 4096;
pub const CONNECT_BUDGET: Duration = Duration::from_millis(250);
const TLS_CONNECT_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub route: String,
    pub query: BTreeMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: Option<SocketAddr>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == lower)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug)]
pub enum ReadError {
    /// The connection produced no request line at all (client closed).
    Empty,
    /// A malformed or oversized request; answer with the status and error.
    Bad(u16, ContractError),
}

/// One line of at most `limit` bytes. The bound applies while reading: an
/// unbounded `read_line` buffered whatever a client sent before any limit
/// was checked. `Ok(None)` is end of stream; a line over the bound, or one
/// that is not UTF-8, is `Err(true)` and `Err(false)` respectively.
fn read_bounded_line(
    reader: &mut BufReader<&TcpStream>,
    limit: usize,
) -> Result<Option<String>, bool> {
    let mut bytes = Vec::new();
    let read = reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| false)?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > limit {
        return Err(true);
    }
    String::from_utf8(bytes).map(Some).map_err(|_| false)
}

fn headers_too_large() -> ReadError {
    ReadError::Bad(
        431,
        ContractError::limit(
            "request headers exceed the 16 KiB bound",
            serde_json::json!({"refused_count": 1, "omitted_count": 1}),
        ),
    )
}

/// Parse one request from a stream with bounded headers and body.
pub fn read_request(stream: &TcpStream, body_limit: usize) -> Result<Request, ReadError> {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream);
    let mut total = 0usize;
    let request_line = match read_bounded_line(&mut reader, MAX_REQUEST_LINE_BYTES) {
        Ok(Some(line)) => line,
        Ok(None) => return Err(ReadError::Empty),
        Err(true) => {
            return Err(ReadError::Bad(
                414,
                ContractError::invariant("request line exceeds the 2 KiB bound"),
            ));
        }
        Err(false) => return Err(ReadError::Empty),
    };
    total += request_line.len();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || path.is_empty() || !version.starts_with("HTTP/1.") {
        return Err(ReadError::Bad(
            400,
            ContractError::invariant("malformed HTTP request line"),
        ));
    }
    if !path.starts_with('/') || path.len() > 2048 {
        return Err(ReadError::Bad(
            400,
            ContractError::invariant("malformed request path"),
        ));
    }
    let mut headers = Vec::new();
    loop {
        let line = match read_bounded_line(&mut reader, MAX_HEADER_BYTES.saturating_sub(total)) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(true) => return Err(headers_too_large()),
            Err(false) => {
                return Err(ReadError::Bad(
                    400,
                    ContractError::invariant("unreadable request headers"),
                ));
            }
        };
        total += line.len();
        if total > MAX_HEADER_BYTES {
            return Err(headers_too_large());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(ReadError::Bad(
                400,
                ContractError::invariant("malformed header line"),
            ));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| value.parse::<usize>())
        .transpose()
        .map_err(|_| ReadError::Bad(400, ContractError::invariant("malformed content-length")))?
        .unwrap_or(0);
    if headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    }) {
        return Err(ReadError::Bad(
            411,
            ContractError::invariant("chunked bodies are not accepted; send content-length"),
        ));
    }
    if content_length > body_limit {
        return Err(ReadError::Bad(
            413,
            ContractError::limit(
                format!("request body exceeds the {body_limit}-byte bound"),
                serde_json::json!({"refused_count": 1, "omitted_count": 1, "bytes": content_length, "ceiling_bytes": body_limit}),
            ),
        ));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|_| {
            ReadError::Bad(
                400,
                ContractError::invariant("request body shorter than content-length"),
            )
        })?;
    }
    let (route, query_text) = path
        .split_once('?')
        .map(|(r, q)| (r.to_owned(), q.to_owned()))
        .unwrap_or((path.clone(), String::new()));
    let mut query = BTreeMap::new();
    for pair in query_text.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(key), percent_decode(value));
    }
    Ok(Request {
        method,
        path,
        route,
        query,
        headers,
        body,
        peer,
    })
}

pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(slice) = bytes.get(index + 1..index + 3) {
                if let Some(value) = std::str::from_utf8(slice)
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                {
                    out.push(value);
                    index += 3;
                    continue;
                }
            }
        }
        if bytes[index] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Response",
    }
}

/// Write one bounded JSON response and close. Error bodies are capped at
/// 4096 bytes by construction (message/remediation truncated).
pub fn respond(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let mut bytes = crate::json::try_canonical_bytes(body)
        .unwrap_or_else(|_| b"{\"error\":{\"code\":\"RUN_INTEGRITY_FAILED\",\"message\":\"response serialization failed\",\"remediation\":\"Preserve evidence.\",\"retryable\":false,\"evidence_id\":\"err_serialize\"}}".to_vec());
    if status >= 400 && bytes.len() > MAX_ERROR_BODY_BYTES {
        let truncated = crate::error::ContractError::internal(
            "error body exceeded the 4096-byte bound and was replaced",
        );
        bytes = crate::json::canonical_bytes(&serde_json::json!({"error": truncated}));
    }
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason(status),
        bytes.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

/// Cut `text` to at most `limit` bytes without splitting a character;
/// `String::truncate` panics inside one, and messages carry client text.
fn truncate_on_char_boundary(text: &mut String, limit: usize) {
    if text.len() > limit {
        let cut = (0..=limit)
            .rev()
            .find(|index| text.is_char_boundary(*index))
            .unwrap_or(0);
        text.truncate(cut);
    }
}

pub fn error_body(error: &ContractError) -> Value {
    let mut compact = error.clone();
    truncate_on_char_boundary(&mut compact.message, 1024);
    truncate_on_char_boundary(&mut compact.remediation, 1024);
    // Structured detail is privacy-minimized by construction (counts, ids,
    // dispositions, digests); it stays in the body only while it is small,
    // so refusals such as a ceiling stop or a CLOCK_SKEW quarantine remain
    // typed for the caller inside the 4096-byte bound.
    let small_detail = compact
        .detail
        .as_ref()
        .filter(|detail| detail.is_object() && crate::json::canonical_bytes(detail).len() <= 1024)
        .cloned();
    compact.detail = small_detail;
    serde_json::json!({"error": compact})
}

/// Parse `http://host:port/base` into a socket address and base path.
/// `allow_non_loopback` is the caller's configured endpoint rule. It belongs
/// here because this is the gate every Company request actually passes: the
/// config check alone lets a routable URL be configured and then refused at
/// the socket, which reads as an outage rather than as a rule.
pub fn parse_url(
    url: &str,
    allow_non_loopback: bool,
    oidc: bool,
) -> Result<(Scheme, String, u16, String), ContractError> {
    let (scheme, rest, default_port) = if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest, "80")
    } else if let Some(rest) = url.strip_prefix("https://").filter(|_| oidc) {
        (Scheme::Https, rest, "443")
    } else if !oidc {
        return Err(ContractError::invariant(
            "Company URL must use http:// over loopback",
        ));
    } else {
        return Err(ContractError::invariant("URL must use http:// or https://"));
    };
    if oidc && url.bytes().any(|byte| byte <= b' ' || byte == 127) {
        return Err(ContractError::invariant(
            "URL contains whitespace or a control byte",
        ));
    }
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((rest, String::new()));
    let (host, port) = authority
        .rsplit_once(':')
        .unwrap_or((authority, default_port));
    let host = host.trim_start_matches('[').trim_end_matches(']');
    // `http://:8421` names no host at all. While the endpoint had to be
    // loopback that was refused by the rule below; once a routable endpoint is
    // permitted it passes here and arrives at the socket as
    // COMPANY_UNREACHABLE, which reads as an outage rather than as the typo in
    // the config that it is.
    if host.is_empty() {
        return Err(ContractError::invariant("Company URL names no host"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| ContractError::invariant("Company URL port is not a number"))?;
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback && !allow_non_loopback {
        return Err(ContractError::invariant(
            "Company URL must name a loopback host",
        ));
    }
    let host = if host == "localhost" && scheme == Scheme::Http {
        "127.0.0.1".to_owned()
    } else {
        host.to_owned()
    };
    Ok((scheme, host, port, path.trim_end_matches('/').to_owned()))
}

pub struct Response {
    pub status: u16,
    pub body: Value,
    pub raw: Vec<u8>,
}

/// The host-start probe gives up 50 ms before the connection budget so that
/// the measured attempt, and the response carrying it, land inside 250 ms.
pub const PROBE_BUDGET: Duration = Duration::from_millis(200);

/// Resolution gets a budget of its own rather than a slice of the connection's.
///
/// A loopback literal resolved for free, so one budget covered both halves
/// honestly. A managed deployment names a cluster Service instead, and CoreDNS
/// on a cold cache, just after a restart, or with `ndots=5` search-path
/// expansion has been measured near 180 ms: out of a shared 250 ms that leaves
/// 70 ms to connect, and a healthy Service answers COMPANY_UNREACHABLE. 250 ms
/// carries that worst case with room over it, and both budgets together are a
/// quarter of the two-second SessionStart p95 (architecture §9), which is the
/// bound that has to hold.
pub const RESOLVE_BUDGET: Duration = Duration::from_millis(250);

/// Why [`within`] gave up. A budget that ran out and a worker that never
/// answered are different failures; they used to be one `None`, and every
/// `None` was reported as the budget, so a resolver thread that panicked read
/// as a slow resolver and sent the reader to the network for a fault in this
/// process.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Abandoned {
    /// The budget ran out with the work still in flight.
    Budget,
    /// The thread ended without sending, or never started at all.
    Worker(String),
}

/// Give `work` its own thread and stop waiting after `budget`.
///
/// The thread is not cancelled, because the standard library offers no way to.
/// It finishes into a channel nobody is reading and ends there, which is the
/// price of bounding a blocking call the platform will not interrupt.
///
/// A thread the OS refuses is reported rather than unwrapped: a panic here
/// leaves the caller with no typed error to refuse with.
///
/// This exists as its own function so the bound can be tested against work that
/// is deliberately slow. A test that only resolves real names proves nothing on
/// a machine whose resolver is fast.
pub(crate) fn within<T: Send + 'static>(
    budget: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Abandoned> {
    // recv_timeout(0) still returns an answer that is already waiting, so work
    // that finishes at once (an IP literal resolves instantly) beat a spent budget.
    if budget.is_zero() {
        return Err(Abandoned::Budget);
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    if let Err(error) = std::thread::Builder::new().spawn(move || {
        let _ = sender.send(work());
    }) {
        return Err(Abandoned::Worker(format!(
            "the thread could not be started ({})",
            error.kind()
        )));
    }
    receiver.recv_timeout(budget).map_err(|error| match error {
        std::sync::mpsc::RecvTimeoutError::Timeout => Abandoned::Budget,
        std::sync::mpsc::RecvTimeoutError::Disconnected => {
            Abandoned::Worker("the thread ended without answering".to_owned())
        }
    })
}

/// Resolve inside resolution's own budget and keep every address the name
/// gave, in the order the resolver put them.
///
/// `to_socket_addrs` blocks with no bound of its own. That cost nothing while a
/// Company endpoint could only be a loopback address, but a name has to be
/// asked for, and an unbounded resolution in front of a bounded connect means
/// the budget stops describing the wait: a slow resolver pushed SessionStart
/// past its own two-second budget while every message still said 250 ms.
///
/// Resolution runs on its own thread so the deadline covers it. A resolver that
/// answers late finds nobody listening and the thread ends on its own; nothing
/// is cancelled because the standard library gives no way to.
fn resolve_within(
    host: &str,
    port: u16,
    budget: Duration,
) -> Result<Vec<SocketAddr>, ContractError> {
    let name = host.to_owned();
    let resolved = within(budget, move || {
        (name.as_str(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>())
            .map_err(|error| error.to_string())
    });
    match resolved {
        Ok(Ok(addresses)) if !addresses.is_empty() => Ok(addresses),
        Ok(Ok(_)) => Err(ContractError::unreachable(
            "Company endpoint does not resolve",
        )),
        Ok(Err(error)) => Err(ContractError::unreachable(format!(
            "Company endpoint does not resolve ({error})"
        ))),
        Err(Abandoned::Budget) => Err(ContractError::unreachable(format!(
            "Company endpoint did not resolve within the {} ms budget",
            budget.as_millis()
        ))),
        Err(Abandoned::Worker(reason)) => Err(ContractError::unreachable(format!(
            "Company endpoint resolution did not run ({reason})"
        ))),
    }
}

/// Connect to the first of `addresses` that answers, inside one budget for the
/// whole attempt.
///
/// A name can give more than one address, and on a dual-stack cluster the
/// resolver can put an AAAA first that a pod with no IPv6 route can never use.
/// Stopping at that first address reported a healthy Service as
/// COMPANY_UNREACHABLE on every request. The budget is a deadline over the
/// whole list rather than one per address, so trying the rest cannot outlast
/// it; an address with no route refuses at once and costs almost nothing.
fn connect_within(
    addresses: &[SocketAddr],
    budget: Duration,
) -> Result<TcpStream, std::io::ErrorKind> {
    let deadline = Instant::now() + budget;
    let mut refusal = std::io::ErrorKind::TimedOut;
    for address in addresses {
        // connect_timeout rejects a zero duration, and a budget already spent
        // is the same answer as one that runs out mid-connect.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(address, remaining) {
            Ok(stream) => return Ok(stream),
            Err(error) => refusal = error.kind(),
        }
    }
    Err(refusal)
}

/// Probe only the connection budget: does the endpoint accept a TCP
/// connection within the probe budget? Nothing is sent; the socket closes
/// at once.
pub fn probe_connect(host: &str, port: u16) -> Result<(), ContractError> {
    let addresses = resolve_within(host, port, RESOLVE_BUDGET)?;
    connect_within(&addresses, PROBE_BUDGET)
        .map(|_stream| ())
        .map_err(|kind| {
            ContractError::unreachable(format!(
                "Company endpoint did not accept a connection within the {} ms budget ({kind})",
                PROBE_BUDGET.as_millis()
            ))
        })
}

/// One client request with the 250 ms (HTTPS: 2 s) connection budget and bounded
/// read/write timeouts. Any failure to connect or answer within budget is
/// `COMPANY_UNREACHABLE`.
#[allow(clippy::too_many_arguments)]
pub fn request(
    scheme: Scheme,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    read_timeout: Duration,
) -> Result<Response, ContractError> {
    let budget = if scheme == Scheme::Https {
        TLS_CONNECT_BUDGET
    } else {
        CONNECT_BUDGET
    };
    let addresses = resolve_within(host, port, budget)?;
    let mut tcp = connect_within(&addresses, budget).map_err(|kind| {
        ContractError::unreachable(format!(
            "Company endpoint did not accept a connection within {} ms ({kind})",
            budget.as_millis()
        ))
    })?;
    tcp.set_read_timeout(Some(read_timeout))
        .map_err(|error| ContractError::io("read timeout", error))?;
    tcp.set_write_timeout(Some(read_timeout))
        .map_err(|error| ContractError::io("write timeout", error))?;
    let _ = tcp.set_nodelay(true);
    let mut tls;
    let stream: &mut dyn ReadWrite = match scheme {
        Scheme::Http => &mut tcp,
        Scheme::Https => {
            static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
            let config = CONFIG.get_or_init(|| {
                let mut roots = rustls::RootCertStore::empty();
                roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
                Arc::new(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth(),
                )
            });
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| ContractError::invariant("TLS endpoint has an invalid server name"))?;
            let connection = rustls::ClientConnection::new(Arc::clone(config), name)
                .map_err(|_| ContractError::unreachable("TLS setup failed"))?;
            tls = rustls::StreamOwned::new(connection, tcp);
            tls.conn.complete_io(&mut tls.sock).map_err(|error| {
                ContractError::unreachable(format!("TLS handshake failed ({error})"))
            })?;
            &mut tls
        }
    };
    let mut text = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty()
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    {
        text.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        text.push_str(name);
        text.push_str(": ");
        text.push_str(value);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    stream
        .write_all(text.as_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|error| {
            ContractError::unreachable(format!(
                "Company endpoint refused the request bytes ({})",
                error.kind()
            ))
        })?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).map_err(|error| {
        ContractError::unreachable(format!(
            "Company endpoint did not answer within the read budget ({})",
            error.kind()
        ))
        .with_detail(serde_json::json!({
            "timeout_observed": true,
            "omitted_count": 1
        }))
    })?;
    if status_line.is_empty() {
        return Err(ContractError::unreachable(
            "Company endpoint closed the connection without a response",
        ));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            ContractError::unreachable("Company endpoint answered with a malformed status line")
        })?;
    let mut content_length = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|error| {
            ContractError::unreachable(format!(
                "Company endpoint headers unreadable ({})",
                error.kind()
            ))
        })?;
        if read == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = Some(value.trim().parse().unwrap_or(0));
            } else if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    // A repository's snapshot carries every fact that governs it plus the
    // versions and traces behind them; a 390-fact repository is 1.1 MB, and a
    // ceiling that refuses it silently withholds the repository's own
    // direction. Responses are signed and verified after this bound, so the
    // bound only protects memory. The full Company snapshot with the corpus is
    // 40 MB at 10,910 facts, so 8 MiB refused every sync.
    let limit = MAX_BODY_BYTES * 512;
    if content_length.is_some_and(|length| length > limit) {
        return Err(ContractError::limit(
            "Company response exceeds the bounded body size",
            serde_json::json!({"refused_count": 1, "omitted_count": 1, "bytes": content_length}),
        ));
    }
    let mut raw = vec![0u8; content_length.unwrap_or(0)];
    if chunked || content_length.is_none() {
        raw.clear();
        let read = reader.by_ref().take(limit as u64 + 1).read_to_end(&mut raw);
        if read.is_err() && (!chunked || raw.is_empty()) {
            return Err(ContractError::unreachable("Company response truncated"));
        }
        if raw.len() > limit {
            return Err(ContractError::limit(
                "Company response exceeds the bounded body size",
                serde_json::json!({"refused_count": 1, "omitted_count": 1}),
            ));
        }
        if chunked {
            raw = crate::classifier::decode_chunked(&raw)
                .map_err(|_| ContractError::unreachable("Company response truncated"))?;
        }
    } else if !raw.is_empty() {
        reader.read_exact(&mut raw).map_err(|error| {
            ContractError::unreachable(format!("Company response truncated ({})", error.kind()))
        })?;
    }
    let body = if raw.is_empty() {
        Value::Null
    } else {
        crate::json::parse_strict_value(&raw)
            .unwrap_or_else(|_| serde_json::from_slice(&raw).unwrap_or(Value::Null))
    };
    Ok(Response { status, body, raw })
}

#[cfg(test)]
mod error_body_tests {
    use super::*;

    #[test]
    fn a_long_multibyte_message_is_cut_on_a_character_boundary() {
        let message = format!("digest algorithm {}", "\u{e9}".repeat(550));
        assert!(!message.is_char_boundary(1024));
        let error = ContractError::refused("CONFIG_INVARIANT", message, "\u{e9}".repeat(600));
        let body = error_body(&error);
        let text = body["error"]["message"].as_str().expect("message");
        assert!(text.len() <= 1024);
        assert!(text.starts_with("digest algorithm "));
        assert!(
            body["error"]["remediation"]
                .as_str()
                .expect("remediation")
                .len()
                <= 1024
        );
    }
}

#[cfg(test)]
mod request_bound_tests {
    use super::*;
    use std::net::TcpListener;

    fn read_sent(bytes: Vec<u8>) -> Result<Request, ReadError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let writer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect");
            // The server stops reading at the bound; a refused write is fine.
            let _ = stream.write_all(&bytes);
        });
        let (stream, _) = listener.accept().expect("accept");
        let result = read_request(&stream, MAX_BODY_BYTES);
        drop(stream);
        let _ = writer.join();
        result
    }

    #[test]
    fn an_overlong_request_line_is_refused_at_the_bound() {
        let mut bytes = b"GET /".to_vec();
        bytes.extend(std::iter::repeat_n(b'a', 4 * 1024 * 1024));
        match read_sent(bytes) {
            Err(ReadError::Bad(status, _)) => assert_eq!(status, 414),
            other => panic!("expected 414, got {other:?}"),
        }
    }

    #[test]
    fn an_overlong_header_line_is_refused_at_the_bound() {
        let mut bytes = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
        bytes.extend(std::iter::repeat_n(b'b', 4 * 1024 * 1024));
        match read_sent(bytes) {
            Err(ReadError::Bad(status, _)) => assert_eq!(status, 431),
            other => panic!("expected 431, got {other:?}"),
        }
    }

    #[test]
    fn an_ordinary_request_still_parses() {
        let request = read_sent(
            b"POST /facts?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        )
        .expect("request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, b"{}");
        assert_eq!(request.header("host"), Some("127.0.0.1"));
    }
}

#[cfg(test)]
mod endpoint_budget_tests {
    use super::*;
    use std::net::TcpListener;

    /// A loopback address with nothing behind it: the connection is refused at
    /// once rather than timing out, which is how an address the pod has no
    /// route to behaves.
    fn closed_loopback_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        address
    }

    /// RFC 5737 TEST-NET-1, reserved for documentation and routed nowhere, so
    /// the attempt runs to its deadline instead of being refused.
    fn blackhole_address() -> SocketAddr {
        "192.0.2.1:8421".parse().expect("address")
    }

    /// The budget has to describe the whole wait, not the half after the name
    /// is known. A name that cannot be answered quickly is the case that used
    /// to escape it: resolution ran to whatever the resolver decided, and only
    /// then did a 250 ms connect begin.
    #[test]
    fn a_name_that_does_not_resolve_still_answers_inside_the_budget() {
        // .invalid is reserved precisely so it can never be registered, so this
        // either fails immediately or hangs on a resolver: both are the case
        // under test, and neither may outlast the bound.
        let started = Instant::now();
        let outcome = probe_connect("kinbase-endpoint-that-cannot-exist.invalid", 8421);
        let elapsed = started.elapsed();
        assert!(outcome.is_err(), "an unresolvable name reported a connection");
        assert!(
            elapsed < Duration::from_secs(2),
            "resolution escaped the budget: {elapsed:?}",
        );
    }

    /// The case the real thing exists for, and the one a resolver test cannot
    /// reach: work that takes longer than the budget must be given up on rather
    /// than waited out. Five seconds against fifty milliseconds is unambiguous
    /// on any machine, fast resolver or not.
    #[test]
    fn work_that_outlasts_its_budget_is_abandoned_not_awaited() {
        let started = Instant::now();
        let outcome = within(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(5));
            "resolved eventually"
        });
        let elapsed = started.elapsed();
        assert_eq!(
            outcome,
            Err(Abandoned::Budget),
            "slow work was waited out to completion",
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the bound did not hold: {elapsed:?}",
        );
    }

    #[test]
    fn work_that_finishes_inside_its_budget_is_returned() {
        assert_eq!(within(Duration::from_secs(5), || 7), Ok(7));
    }

    /// The deterministic half of the same property. The test above depends on
    /// how fast a resolver says no, which on a machine that answers instantly
    /// would pass with or without a bound. This one cannot: a budget already
    /// spent has to be refused rather than waited out.
    #[test]
    fn a_spent_budget_refuses_rather_than_resolving() {
        let outcome = resolve_within("127.0.0.1", 8421, Duration::ZERO);
        let error = outcome.expect_err("a zero budget resolved anyway");
        assert!(
            error.message.contains("did not resolve within"),
            "refused for the wrong reason: {}",
            error.message,
        );
    }

    /// A name can answer with more than one address, and keeping only the
    /// first threw away the fallback. `localhost` is the one name a test can
    /// count on, and where it is dual-stack it answers with two: exactly the
    /// shape a cluster Service takes, AAAA first.
    #[test]
    fn every_address_a_name_resolves_to_is_kept() {
        let expected: Vec<SocketAddr> = ("localhost", 8421)
            .to_socket_addrs()
            .expect("localhost resolves")
            .collect();
        let addresses =
            resolve_within("localhost", 8421, RESOLVE_BUDGET).expect("localhost resolves");
        assert_eq!(addresses, expected);
    }

    /// The failure this exists for: on a dual-stack cluster the resolver puts
    /// an AAAA first that a pod with no IPv6 route cannot use, and a healthy
    /// Service answered COMPANY_UNREACHABLE on every request because the next
    /// address was never tried. A closed loopback port refuses the same way a
    /// routeless address does.
    #[test]
    fn the_next_address_is_tried_when_the_first_one_refuses() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let healthy = listener.local_addr().expect("address");
        let stream = connect_within(&[closed_loopback_address(), healthy], CONNECT_BUDGET)
            .expect("a healthy second address was never tried");
        assert_eq!(stream.peer_addr().expect("peer"), healthy);
    }

    /// Falling through the list may not multiply the budget by the length of
    /// it. Two addresses that each run to the deadline on their own still have
    /// to answer inside one budget.
    #[test]
    fn trying_every_address_stays_inside_one_budget() {
        let started = Instant::now();
        let outcome = connect_within(&[blackhole_address(), blackhole_address()], PROBE_BUDGET);
        let elapsed = started.elapsed();
        let refusal = outcome
            .map(|_| ())
            .expect_err("an address routed nowhere reported a connection");
        // Without this the test passes on a host that refuses the address at
        // once, where no budget was ever under test.
        assert_eq!(
            refusal,
            std::io::ErrorKind::TimedOut,
            "the address refused rather than running to the deadline",
        );
        assert!(
            elapsed < PROBE_BUDGET * 2,
            "each address took a budget of its own: {elapsed:?}",
        );
    }

    /// Resolution used to be paid out of the connection's budget: whatever was
    /// left once the name was known is all the connection got, so a CoreDNS
    /// cold cache that spent 180 ms of 250 left 70 ms and a healthy Service
    /// answered COMPANY_UNREACHABLE. The two are separate now, so the
    /// connection runs to its own deadline however long the name took.
    ///
    /// The resolver is slow on purpose, as in the bound test above: no real
    /// name is reliably slow, and this split only shows against one that is.
    #[test]
    fn a_resolution_that_spends_its_own_budget_leaves_the_connection_a_whole_one() {
        let addresses = within(RESOLVE_BUDGET, || {
            std::thread::sleep(RESOLVE_BUDGET - Duration::from_millis(20));
            vec![blackhole_address()]
        })
        .expect("a resolver inside its own budget was abandoned");
        let started = Instant::now();
        let outcome = connect_within(&addresses, CONNECT_BUDGET);
        let elapsed = started.elapsed();
        assert!(
            outcome.is_err(),
            "an address routed nowhere reported a connection",
        );
        assert!(
            elapsed >= CONNECT_BUDGET,
            "the connection gave up on what resolution left, not on its own budget: {elapsed:?}",
        );
    }

    /// The probe gives the connection `PROBE_BUDGET`, not the 250 ms the
    /// message used to claim. A message naming a budget the code does not use
    /// sends whoever reads it to measure the wrong thing.
    #[test]
    fn a_refused_probe_names_the_budget_the_connection_actually_had() {
        let port = closed_loopback_address().port();
        let error = probe_connect("127.0.0.1", port).expect_err("a closed port connected");
        assert!(
            error.message.contains("200 ms"),
            "the message named a budget the probe does not use: {}",
            error.message,
        );
    }

    /// A thread that died and a budget that ran out were both `None`, and every
    /// `None` was reported as the budget, so a worker that panicked read as a
    /// slow resolver. The panic this provokes prints to stderr; that is the
    /// worker dying on purpose, not a failure.
    #[test]
    fn a_worker_that_dies_is_not_reported_as_a_spent_budget() {
        let outcome = within(Duration::from_secs(5), || -> u8 {
            panic!("the resolver worker died")
        });
        match outcome {
            Err(Abandoned::Worker(reason)) => assert!(
                reason.contains("without answering"),
                "reported for the wrong reason: {reason}",
            ),
            other => panic!("a dead worker was reported as {other:?}"),
        }
    }
}

#[cfg(test)]
mod endpoint_url_tests {
    use super::*;

    /// An empty host is a typo in the config, not an outage. While the endpoint
    /// had to be loopback the loopback rule refused it by accident; once a
    /// routable endpoint is permitted it reached the socket and came back as
    /// COMPANY_UNREACHABLE, which points at a healthy network.
    #[test]
    fn a_company_url_with_no_host_is_refused_as_configuration() {
        let error = parse_url("http://:8421/base", true, false)
            .expect_err("a URL naming no host was accepted");
        assert_eq!(error.code, "CONFIG_INVARIANT");
    }
}
