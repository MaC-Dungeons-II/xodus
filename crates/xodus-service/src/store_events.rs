// SPDX-License-Identifier: GPL-3.0-only
//! Closed, credential-free diagnostic protocol. No free-form remote strings.
use std::sync::atomic::{AtomicUsize, Ordering};
static COUNT: AtomicUsize=AtomicUsize::new(0);
pub fn emit(phase:&str, outcome:&str) {
    if !["prepare","catalog","authentication","window_open","bootstrap_started","bootstrap_ready","bootstrap_error","window_ready","checkout_ready","load_timeout","session_timeout","expired","error","complete","cancel"].contains(&phase)
        || !["started","passed","failed","cancelled","expired","timeout","unsupported","busy","succeeded"].contains(&outcome) {return;}
    let seq=COUNT.fetch_add(1,Ordering::Relaxed);
    if seq==2048 {eprintln!("[flightdeck-store-events-truncated]");}
    if seq<2048 {eprintln!("[flightdeck-store-event] time_ms={} seq={seq} phase={phase} outcome={outcome}",chrono::Utc::now().timestamp_millis());}
}
pub fn launch() {
    let Ok(raw)=std::env::var("FLIGHTDECK_STORE_LAUNCH") else{return;};
    if raw.len()>4096{return;}
    let Ok(v)=serde_json::from_str::<serde_json::Value>(&raw) else{return;};
    let Some(version)=v["launcher"].as_str().filter(|s|s.len()<40 && s.bytes().all(|b|b.is_ascii_alphanumeric()||b".-+".contains(&b))) else{return;};
    let Some(files)=v["files"].as_object() else{return;};
    const NAMES:[&str;7]=["cli","broker","storage","proxy","builtin","prefix_builtin","unix"];
    if files.len()!=NAMES.len() || !NAMES.iter().all(|name|files.get(*name).and_then(serde_json::Value::as_str).is_some_and(|s|s.len()==64 && s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)))){return;}
    let safe=serde_json::json!({"launcher":version,"files":files});
    eprintln!("[flightdeck-store-build] {safe}");
}
pub fn progress(line:&str)->Option<&str> {
    let value=line.strip_prefix("FLIGHTDECK_STORE_PROGRESS ")?;
    let v:serde_json::Value=serde_json::from_str(value).ok()?;
    // Return static constants, never a reference to untrusted text.
    ["bootstrap_started","bootstrap_ready","bootstrap_error","window_ready","checkout_ready","load_timeout","session_timeout","expired","error"].into_iter().find(|p|v["phase"]==*p)
}
#[cfg(test)] mod tests {
    use super::*;
    #[test]fn discard_native_stderr_and_unknown_values(){
        assert_eq!(progress("Gtk warning token=secret"),None);
        assert_eq!(progress("FLIGHTDECK_STORE_PROGRESS {\"phase\":\"https://private\"}"),None);
        assert_eq!(progress("FLIGHTDECK_STORE_PROGRESS {\"phase\":\"checkout_ready\"}"),Some("checkout_ready"));
    }
}
