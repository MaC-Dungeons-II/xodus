//! Xbox session file for the mcd2-crossover xgameruntime adapter, minted from
//! the xodus account (M(a)C Dungeons II launcher). Replaces the adapter's own
//! Python sign-in helper so the launcher needs a single Microsoft sign-in.
//!
//! Packet layout (helper/bridge.py, struct '<QQQII32s512s49152sQ'):
//!   magic, expiry (FILETIME), xuid, age group, privileges-known, privilege
//!   bitmap[32], gamertag fields 4x128, auth headers 3x16384 (xboxlive,
//!   minecraftservices, playfab), generation.
//! Token values are written only to the private session file, never printed.
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use xodus::tokens::TokenManager;

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

async fn mint(client: &reqwest::Client, tokens: &TokenManager) -> Result<Session, &'static str> {
    xodus::tokens::session::ensure_session(tokens).await.map_err(|_| "session")?;
    let (mut auth, sisu, device) = xodus::auth::do_sisu(client, tokens, MSA_APP_ID, TITLE_ID)
        .await
        .map_err(|_| "sisu")?;
    let mut headers = Vec::new();
    let mut expires = i64::MAX;
    let mut claims: Option<std::collections::HashMap<String, String>> = None;
    let mut xuids = std::collections::HashSet::new();
    for rp in RELYING_PARTIES {
        let xsts = auth
            .get_xsts_token(Some(&device), Some(&sisu.title_token), Some(&sisu.user_token), rp)
            .await
            .map_err(|_| "xsts")?;
        let xui = xsts
            .display_claims
            .as_ref()
            .and_then(|c| c.xui.first())
            .ok_or("claims")?
            .clone();
        let uhs = xui.get("uhs").ok_or("uhs")?.clone();
        if let Some(xid) = xui.get("xid") {
            xuids.insert(xid.clone());
        }
        if rp == RELYING_PARTIES[0] {
            claims = Some(xui);
        }
        expires = expires.min(xsts.not_after.timestamp());
        headers.push(format!("XBL3.0 x={uhs};{}", xsts.token));
    }
    let claims = claims.ok_or("claims")?;
    let xuid: u64 = claims.get("xid").ok_or("xid")?.parse().map_err(|_| "xid")?;
    if xuids.len() != 1 || xuid == 0 {
        return Err("identity");
    }
    if expires <= now_secs() + 120 {
        return Err("expiring");
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
    field(&mut packet, claims.get("gtg").map(String::as_str).unwrap_or(""), 128)?;
    for _ in 0..3 {
        field(&mut packet, "", 128)?;
    }
    for header in &headers {
        field(&mut packet, header, 16384)?;
    }
    packet.extend_from_slice(&generation.to_le_bytes());
    debug_assert_eq!(packet.len(), PACKET_SIZE);
    Ok(Session { packet, expires, generation })
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
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

pub async fn run(client: &reqwest::Client, tokens: &TokenManager, home: String, serve: bool) -> ExitCode {
    let home = PathBuf::from(home);
    if std::fs::create_dir_all(&home).is_err() {
        return ExitCode::FAILURE;
    }
    let session_path = home.join("session.bin");
    let renew = |reason: &'static str| {
        let session_path = session_path.clone();
        async move {
            match mint(client, tokens).await {
                Ok(s) => {
                    if atomic_write(&session_path, &s.packet).is_err() {
                        eprintln!("mac-session: write failed");
                        return None;
                    }
                    println!("{}", serde_json::json!({"session": "ready", "reason": reason, "expires": s.expires}));
                    Some(s.generation)
                }
                Err(stage) => {
                    println!("{}", serde_json::json!({"session": "failed", "stage": stage}));
                    None
                }
            }
        }
    };
    let needs_renewal = read_session(&session_path).is_none_or(|(_, e)| e < now_secs() + 600);
    if needs_renewal && renew("start").await.is_none() {
        return ExitCode::from(EXIT_LOGIN_REQUIRED);
    }
    if !serve {
        return ExitCode::SUCCESS;
    }
    let mut last_attempt = 0i64;
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
                let mut code = ERROR;
                let mut generation = 0u64;
                if let Ok(data) = std::fs::read(&path) {
                    if data.len() == 16 && read_u64(&data, 0) == REQUEST_MAGIC {
                        let old = read_u64(&data, 8);
                        if read_session(&session_path).is_none_or(|(g, _)| g == old) {
                            renew("forced").await;
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
                atomic_write(&home.join(format!("{stem}.res")), &response).ok();
                std::fs::remove_file(&path).ok();
            }
        }
        let t = now_secs();
        if read_session(&session_path).is_none_or(|(_, e)| e - t < 300) && t - last_attempt > 60 {
            last_attempt = t;
            renew("expiry").await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
