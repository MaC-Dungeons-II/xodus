//! Xbox session file for the mcd2-crossover xgameruntime adapter, minted from
//! the xodus account (M(a)C Dungeons II launcher). Replaces the adapter's own
//! Python sign-in helper so the launcher needs a single Microsoft sign-in.
//!
//! Packet layout (helper/bridge.py, struct '<QQQII32s512s49152sQ'):
//!   magic, expiry (FILETIME), xuid, age group, privileges-known, privilege
//!   bitmap[32], gamertag fields 4x128, auth headers 3x16384 (xboxlive,
//!   minecraftservices, playfab), generation.
//! Token values are written only to the private session file, never printed.
//!
//! With --check nothing is written: the account is signed in to the same
//! Xbox services and only the outcome is reported (exit 0, 77 sign in again,
//! 69 offline). The launcher uses that since its runtime signs in by itself.
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::FutureExt;
use xodus::api::live::{RSTError, ResponseStep};
use xodus::tokens::TokenManager;
use xodus::tokens::session::SessionError;
use xodus::tokens::store::TokenStoreError;

const MAGIC: u64 = 0x3247_4449_5242_5858;
const REQUEST_MAGIC: u64 = 0x3151_4552_4243_4447;
const ERROR: u64 = 0x8000_4005;
const MSA_APP_ID: &str = "00000000497C1B94"; // Minecraft Dungeons II MSAAppId
const TITLE_ID: i64 = 0x6B9D_E498;
const RELYING_PARTIES: [&str; 3] = [
    "http://xboxlive.com",
    "rp://api.minecraftservices.com/",
    "http://playfab.xboxlive.com/",
];
const PACKET_SIZE: usize = 8 * 3 + 4 * 2 + 32 + 512 + 49152 + 8;
/// FILETIME (100 ns ticks since 1601-01-01) of the Unix epoch.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;
/// Exit code that tells the launcher an interactive login is needed.
const EXIT_LOGIN_REQUIRED: u8 = 77;
/// Exit code for network or service unavailable (EX_UNAVAILABLE).
const EXIT_UNAVAILABLE: u8 = 69;
/// Deadline for each network step of a mint.
const NETWORK_DEADLINE: Duration = Duration::from_secs(30);
/// Minimum seconds between renewal attempts (expiry-driven or forced).
const RENEW_THROTTLE: i64 = 60;
/// Request files shorter than a full request are left alone this long, in
/// case the adapter is still writing them.
const REQUEST_GRACE: Duration = Duration::from_secs(2);

struct Session {
    packet: Vec<u8>,
    expires: i64,
    generation: u64,
}

fn since_epoch() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
}

fn now_secs() -> i64 {
    since_epoch().as_secs() as i64
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn field(out: &mut Vec<u8>, value: &str, size: usize) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() >= size || bytes.contains(&0) {
        return Err("field-size");
    }
    out.extend_from_slice(bytes);
    out.resize(out.len() + (size - bytes.len()), 0);
    Ok(())
}

/// Outcome class of a failed session operation; also the process exit code
/// of the one-shot check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The user must sign in again (no refresh token, or Microsoft rejected it).
    Login,
    /// Network or service unavailable (connect, DNS, timeout, 5xx, 429).
    Network,
    /// Anything else.
    Other,
}

impl Failure {
    fn code(self) -> u8 {
        match self {
            Failure::Login => EXIT_LOGIN_REQUIRED,
            Failure::Network => EXIT_UNAVAILABLE,
            Failure::Other => 1,
        }
    }
}

type MintError = (&'static str, Failure);

fn session_class(err: SessionError) -> Failure {
    match err {
        SessionError::SignInRequired => Failure::Login,
        SessionError::Connection | SessionError::Timeout => Failure::Network,
        SessionError::Keyring | SessionError::AccountChanged | SessionError::InvalidResponse => Failure::Other,
    }
}

fn status_class(status: u16) -> Failure {
    if status >= 500 || status == 429 { Failure::Network } else { Failure::Other }
}

fn rst_class(err: &RSTError) -> Failure {
    match err {
        RSTError::AuthenticationRejected => Failure::Login,
        RSTError::Request(_) => Failure::Network,
        RSTError::Response { step: ResponseStep::HttpStatus | ResponseStep::RateLimit, .. } => Failure::Network,
        RSTError::Response { source, .. } => rst_class(source),
        _ => Failure::Other,
    }
}

fn xal_class(err: &xodus::xal::Error) -> Failure {
    match err {
        xodus::xal::Error::ReqwestError(e) => {
            if e.is_timeout() || e.is_connect() || e.is_request() || e.is_body() {
                Failure::Network
            } else {
                e.status().map_or(Failure::Other, |s| status_class(s.as_u16()))
            }
        }
        // Xbox answered with a non-JSON body; only its status is meaningful.
        // 401/403 are not treated as a sign-out: they also come from clock
        // skew in the signed request.
        xodus::xal::Error::JsonHttpResponseError { status, .. } => status_class(status.as_u16()),
        _ => Failure::Other,
    }
}

/// Classifies an error from the xodus/xal sign-in stack. Only an explicit
/// "no credential" or Microsoft rejection asks the user to sign in again.
fn classify(err: &(dyn std::error::Error + 'static)) -> Failure {
    if let Some(e) = err.downcast_ref::<SessionError>() {
        return session_class(*e);
    }
    if let Some(e) = err.downcast_ref::<TokenStoreError>() {
        return if matches!(e, TokenStoreError::NotFound) { Failure::Login } else { Failure::Other };
    }
    if let Some(e) = err.downcast_ref::<RSTError>() {
        return rst_class(e);
    }
    if let Some(e) = err.downcast_ref::<xodus::xal::Error>() {
        return xal_class(e);
    }
    if let Some(e) = err.downcast_ref::<reqwest::Error>() {
        if e.is_timeout() || e.is_connect() || e.is_request() || e.is_body() {
            return Failure::Network;
        }
        return e.status().map_or(Failure::Other, |s| status_class(s.as_u16()));
    }
    Failure::Other
}

/// Runs one network step with a deadline; a timeout counts as Network.
async fn bounded<T, E>(
    stage: &'static str,
    future: impl Future<Output = Result<T, E>>,
    class: impl FnOnce(E) -> Failure,
) -> Result<T, MintError> {
    match tokio::time::timeout(NETWORK_DEADLINE, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err((stage, class(err))),
        Err(_) => Err((stage, Failure::Network)),
    }
}

async fn mint(client: &reqwest::Client, tokens: &TokenManager) -> Result<Session, MintError> {
    bounded("device", xodus::tokens::device::ensure_device_credentials(client, tokens), session_class).await?;
    bounded("session", xodus::tokens::session::ensure_session(tokens), session_class).await?;
    let (mut auth, sisu, device) =
        bounded("sisu", xodus::auth::do_sisu(client, tokens, MSA_APP_ID, TITLE_ID), |e| classify(&*e)).await?;
    let mut headers = Vec::new();
    let mut expires = i64::MAX;
    let mut claims: Option<std::collections::HashMap<String, String>> = None;
    let mut xuids = std::collections::HashSet::new();
    for rp in RELYING_PARTIES {
        let xsts = bounded(
            "xsts",
            auth.get_xsts_token(Some(&device), Some(&sisu.title_token), Some(&sisu.user_token), rp),
            |e| xal_class(&e),
        )
        .await?;
        let xui = xsts
            .display_claims
            .as_ref()
            .and_then(|c| c.xui.first())
            .ok_or(("claims", Failure::Other))?
            .clone();
        let uhs = xui.get("uhs").ok_or(("uhs", Failure::Other))?.clone();
        if let Some(xid) = xui.get("xid") {
            xuids.insert(xid.clone());
        }
        if rp == RELYING_PARTIES[0] {
            claims = Some(xui);
        }
        expires = expires.min(xsts.not_after.timestamp());
        headers.push(format!("XBL3.0 x={uhs};{}", xsts.token));
    }
    let claims = claims.ok_or(("claims", Failure::Other))?;
    let xuid: u64 = claims
        .get("xid")
        .ok_or(("xid", Failure::Other))?
        .parse()
        .map_err(|_| ("xid", Failure::Other))?;
    if xuids.len() != 1 || xuid == 0 {
        return Err(("identity", Failure::Other));
    }
    // Server-issued expiry judged by the local clock: a skewed clock must not
    // look like a sign-out, so this is never a login failure.
    if expires <= now_secs() + 120 {
        return Err(("expiring", Failure::Other));
    }
    let age: u32 = match claims.get("agg").map(String::as_str) {
        Some("Child") => 1,
        Some("Teen") => 2,
        Some("Adult") => 3,
        _ => 0,
    };
    let mut privileges = [0u8; 32];
    let privileges_known = claims.get("prv").is_some();
    if let Some(prv) = claims.get("prv") {
        for v in prv.split_whitespace().filter_map(|item| item.parse::<usize>().ok()) {
            if v < 256 {
                privileges[v / 8] |= 1 << (v % 8);
            }
        }
    }
    let generation = since_epoch().as_nanos() as u64;
    let mut packet = Vec::with_capacity(PACKET_SIZE);
    packet.extend_from_slice(&MAGIC.to_le_bytes());
    let filetime = (expires as u64) * FILETIME_TICKS_PER_SEC + FILETIME_UNIX_EPOCH;
    packet.extend_from_slice(&filetime.to_le_bytes());
    packet.extend_from_slice(&xuid.to_le_bytes());
    packet.extend_from_slice(&age.to_le_bytes());
    packet.extend_from_slice(&(privileges_known as u32).to_le_bytes());
    packet.extend_from_slice(&privileges);
    let field_error = |e| (e, Failure::Other);
    field(&mut packet, claims.get("gtg").map(String::as_str).unwrap_or(""), 128).map_err(field_error)?;
    for _ in 0..3 {
        field(&mut packet, "", 128).map_err(field_error)?;
    }
    for header in &headers {
        field(&mut packet, header, 16384).map_err(field_error)?;
    }
    packet.extend_from_slice(&generation.to_le_bytes());
    debug_assert_eq!(packet.len(), PACKET_SIZE);
    Ok(Session { packet, expires, generation })
}

/// Writes `data` to `path` through a private (0600) temp file and a rename.
/// The temp file is created exclusively so the mode always applies, and it is
/// removed again if anything fails.
fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    match std::fs::remove_file(&tmp) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    let result = f.write_all(data).and_then(|()| f.sync_all()).and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    result
}

/// Generation and expiry (Unix seconds) of a valid session file, if any.
fn read_session(path: &Path) -> Option<(u64, i64)> {
    let data = std::fs::read(path).ok()?;
    if data.len() != PACKET_SIZE || read_u64(&data, 0) != MAGIC {
        return None;
    }
    let filetime = read_u64(&data, 8);
    let expires = (filetime.saturating_sub(FILETIME_UNIX_EPOCH) / FILETIME_TICKS_PER_SEC) as i64;
    let generation = read_u64(&data, PACKET_SIZE - 8);
    Some((generation, expires))
}

/// True for a request file that may still be being written: shorter than a
/// full request and modified within REQUEST_GRACE (either direction, so a
/// slightly skewed mtime doesn't matter).
fn still_being_written(meta: &std::fs::Metadata) -> bool {
    if meta.len() >= 16 {
        return false;
    }
    let Ok(modified) = meta.modified() else { return false };
    let age = match SystemTime::now().duration_since(modified) {
        Ok(age) => age,
        Err(ahead) => ahead.duration(),
    };
    age < REQUEST_GRACE
}

pub async fn run(client: &reqwest::Client, tokens: &TokenManager, home: String, serve: bool, check: bool) -> ExitCode {
    if check {
        let minted = std::panic::AssertUnwindSafe(mint(client, tokens))
            .catch_unwind()
            .await
            .unwrap_or(Err(("panic", Failure::Other)));
        return match minted {
            Ok(s) => {
                println!("{}", serde_json::json!({"session": "ready", "reason": "check", "expires": s.expires}));
                ExitCode::SUCCESS
            }
            Err((stage, failure)) => {
                println!("{}", serde_json::json!({"session": "failed", "stage": stage, "code": failure.code()}));
                ExitCode::from(failure.code())
            }
        };
    }
    let home = PathBuf::from(home);
    if let Err(err) = std::fs::create_dir_all(&home) {
        eprintln!("mac-session: cannot create session directory: {err}");
        return ExitCode::FAILURE;
    }
    let session_path = home.join("session.bin");
    let renew = |reason: &'static str| {
        let session_path = session_path.clone();
        async move {
            // A panic deep in the sign-in stack must not take --serve down.
            let minted = std::panic::AssertUnwindSafe(mint(client, tokens))
                .catch_unwind()
                .await
                .unwrap_or(Err(("panic", Failure::Other)));
            match minted {
                Ok(s) => {
                    if let Err(err) = atomic_write(&session_path, &s.packet) {
                        eprintln!("mac-session: write failed: {err}");
                        println!("{}", serde_json::json!({"session": "failed", "stage": "write", "code": Failure::Other.code()}));
                        return Err(Failure::Other);
                    }
                    println!("{}", serde_json::json!({"session": "ready", "reason": reason, "expires": s.expires}));
                    Ok(s.generation)
                }
                Err((stage, failure)) => {
                    println!("{}", serde_json::json!({"session": "failed", "stage": stage, "code": failure.code()}));
                    Err(failure)
                }
            }
        }
    };
    let mut last_attempt = i64::MIN;
    let needs_renewal = read_session(&session_path).is_none_or(|(_, e)| e < now_secs() + 600);
    if needs_renewal {
        last_attempt = now_secs();
        if let Err(failure) = renew("start").await {
            // The one-shot check reports the class. --serve keeps running and
            // retries unless the user has to sign in again.
            if !serve || failure == Failure::Login {
                return ExitCode::from(failure.code());
            }
        }
    }
    if !serve {
        return ExitCode::SUCCESS;
    }
    loop {
        // Adapter-forced refresh requests: refresh-<16 hex>.req -> .res
        if let Ok(entries) = std::fs::read_dir(&home) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some(stem) = name.strip_suffix(".req") else { continue };
                if !stem.starts_with("refresh-") || stem.len() != 24 || !stem[8..].bytes().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let path = entry.path();
                if std::fs::metadata(&path).is_ok_and(|m| still_being_written(&m)) {
                    continue;
                }
                let mut code = ERROR;
                let mut generation = 0u64;
                if let Ok(data) = std::fs::read(&path) {
                    if data.len() == 16 && read_u64(&data, 0) == REQUEST_MAGIC {
                        let old = read_u64(&data, 8);
                        // Same throttle as expiry renewal: while offline, a
                        // burst of requests answers from the current file.
                        let t = now_secs();
                        if read_session(&session_path).is_none_or(|(g, _)| g == old)
                            && t.saturating_sub(last_attempt) >= RENEW_THROTTLE
                        {
                            last_attempt = t;
                            let _ = renew("forced").await;
                        }
                        if let Some((g, e)) = read_session(&session_path) {
                            if g != old && e > now_secs() {
                                code = 0;
                                generation = g;
                            }
                        }
                    }
                }
                let mut response = Vec::with_capacity(16);
                response.extend_from_slice(&code.to_le_bytes());
                response.extend_from_slice(&generation.to_le_bytes());
                if let Err(err) = atomic_write(&home.join(format!("{stem}.res")), &response) {
                    eprintln!("mac-session: reply write failed: {err}");
                }
                std::fs::remove_file(&path).ok();
            }
        }
        let t = now_secs();
        if read_session(&session_path).is_none_or(|(_, e)| e - t < 300) && t.saturating_sub(last_attempt) >= RENEW_THROTTLE {
            last_attempt = t;
            let _ = renew("expiry").await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
