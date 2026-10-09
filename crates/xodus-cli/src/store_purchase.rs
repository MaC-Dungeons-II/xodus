// SPDX-License-Identifier: GPL-3.0-only
//! Microsoft-hosted payment UI. Receives credentials only over an inherited
//! pipe; the host never collects payment details or submits an order itself.
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tao::{dpi::LogicalSize, event::{Event, WindowEvent}, event_loop::{ControlFlow, EventLoopBuilder},
    platform::run_return::EventLoopExtRunReturn, window::WindowBuilder};
use wry::{WebViewBuilder, NewWindowResponse, PageLoadEvent};

// This public, unauthenticated document establishes the genuine Microsoft
// origin before the confirmation form is submitted. Never forge an Origin or
// Referer header or disable WebKit's origin/TLS checks.
const BOOTSTRAP_URL: &str = "https://www.microsoft.com/store/purchase/buynowui/prefetch/buynow";

fn valid_id(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
fn config_valid(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.len() == 7)
        && valid_id(v["productId"].as_str().unwrap_or(""), 12)
        && valid_id(v["skuId"].as_str().unwrap_or(""), 4)
        && valid_id(v["availabilityId"].as_str().unwrap_or(""), 12)
        && valid_id(v["market"].as_str().unwrap_or(""), 2)
        && v["locale"].as_str().is_some_and(|s| (2..=35).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphabetic() || c == b'-'))
        && v["xToken"].as_str().is_some_and(|s| s.starts_with("XBL3.0 x=") && s.len() < 65536 && !s.chars().any(char::is_control))
        && v["expiresAt"].as_i64().is_some_and(|t| t > chrono::Utc::now().timestamp() + 30)
}
fn result(v: &Value, nonce: &str) -> Option<Value> {
    if v["nonce"] != nonce { return None; }
    if let Some(phase) = v["phase"].as_str().filter(|p| ["bootstrap_started", "bootstrap_error", "window_ready", "checkout_ready", "load_timeout", "session_timeout", "expired", "error"].contains(p)) {
        return Some(json!({"phase":phase}));
    }
    match v["status"].as_str()? {
        "success" => {
            let order = v["orderId"].as_str()?;
            if order.is_empty() || order.len() > 128 || !order.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_:".contains(&c)) { return None; }
            Some(json!({"status":"Succeeded", "orderId":order}))
        }
        "cancel" | "cancelEscKey" | "cancelXButton" => Some(json!({"status":"Cancelled"})),
        "error" | "bootstrap_error" => Some(json!({"status":"Error"})),
        "expired" => Some(json!({"status":"Expired"})),
        "load_timeout" | "session_timeout" => Some(json!({"status":"Timeout"})),
        _ => None,
    }
}
pub(crate) fn html(config: &Value, nonce: &str) -> String {
    render(config, nonce, "checkout")
}
pub(crate) fn render(config: &Value, nonce: &str, mode: &str) -> String {
    assert!(["checkout", "bootstrap", "bootstrap_error"].contains(&mode));
    let payload = serde_json::to_string(config).unwrap().replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026");
    include_str!("store_purchase.html").replace("__NONCE__", nonce).replace("__MODE__", mode).replace("__CONFIG__", &payload)
}
pub(crate) fn bootstrap_script(content: &str, nonce: &str, url: &str) -> String {
    // evaluate_script runs in the main document only. The secret IPC nonce is
    // never put in an initialization script shared with third-party frames.
    format!(r#"(() => {{
      if (window !== window.top || location.href !== {url} || location.origin !== new URL({url}).origin) {{
        window.ipc.postMessage(JSON.stringify({{nonce:{nonce},phase:'bootstrap_error'}})); return;
      }}
      document.open(); document.write({content}); document.close();
    }})()"#,
        url=serde_json::to_string(url).unwrap(), nonce=serde_json::to_string(nonce).unwrap(),
        content=serde_json::to_string(content).unwrap())
}
pub(crate) fn bootstrap_listener(url: String, loaded: impl Fn() + 'static) -> impl Fn(PageLoadEvent, String) {
    let committed = std::cell::Cell::new(false);
    move |event, current| {
        // A cancelled about:blank load may finish after its URI has changed.
        // PageLoadEvent::Started represents WebKit's document commit.
        if matches!(event, PageLoadEvent::Started) { committed.set(current == url); }
        if matches!(event, PageLoadEvent::Finished) && current == url && committed.get() { loaded(); }
    }
}
pub(crate) fn attach_webview<'a>(window: &'a tao::window::Window, builder: WebViewBuilder<'a>) -> Result<wry::WebView, ()> {
    // Tao already owns a GTK window. Attaching another foreign X11 window can
    // hide the webview behind Tao's container; the native container also works
    // under Wayland and tracks layout/resize events.
    #[cfg(target_os = "linux")]
    {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let container = window.default_vbox().ok_or(())?;
        builder.build_gtk(container).map_err(|_| ())
    }
    #[cfg(not(target_os = "linux"))]
    builder.build(window).map_err(|_| ())
}
pub fn run() -> std::process::ExitCode {
    let result = show().unwrap_or_else(|_| json!({"status":"Error"}));
    // Never serialize config, credentials, server error messages or URLs.
    let _ = writeln!(std::io::stdout(), "{result}");
    std::process::ExitCode::SUCCESS
}
fn show() -> Result<Value, ()> {
    let mut input = String::new();
    std::io::stdin().take(70001).read_to_string(&mut input).map_err(|_| ())?;
    let config: Value = serde_json::from_str(&input).map_err(|_| ())?;
    if input.len() > 70000 || !config_valid(&config) { return Err(()); }
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let content = html(&config, &nonce);
    let expiry = config["expiresAt"].as_i64().ok_or(())?;
    let mut events = EventLoopBuilder::<Value>::with_user_event().build();
    let window = WindowBuilder::new().with_title("Microsoft Store — Flightdeck")
        .with_inner_size(LogicalSize::new(720., 820.)).build(&events).map_err(|_| ())?;
    let proxy = events.create_proxy();
    // On Linux Wry reports the top frame URI for iframe IPC too. The secret
    // nonce lives only in the isolated top document, never in an init script.
    let ipc_nonce = nonce.clone();
    let loaded = events.create_proxy();
    let builder = WebViewBuilder::new().with_incognito(true).with_html(render(&config, &nonce, "bootstrap"))
        .with_devtools(false)
        .with_on_page_load_handler(bootstrap_listener(BOOTSTRAP_URL.into(), move || {
            let _ = loaded.send_event(json!({"native_bootstrap_loaded":true}));
        }))
        .with_new_window_req_handler(|url, _| {
            if url.starts_with("https://") { NewWindowResponse::Allow } else { NewWindowResponse::Deny }
        })
        .with_ipc_handler(move |request| {
            if request.body().len() > 4096 { return; }
            if let Ok(v) = serde_json::from_str::<Value>(request.body()) {
                if let Some(value) = result(&v, &ipc_nonce) { let _ = proxy.send_event(value); }
            }
        });
    let webview = attach_webview(&window, builder)?;
    let started = Instant::now();
    let mut outcome = json!({"status":"Cancelled"});
    let mut progress_count = 0;
    let mut bootstrap_requested = false;
    let mut bootstrap_attached = false;
    let mut bootstrap_failed = false;
    let mut host_ready = false;
    events.run_return(|event, _, flow| {
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(250));
        match event {
            Event::UserEvent(value) if value["native_bootstrap_loaded"] == true => {
                if bootstrap_requested && !bootstrap_attached && !bootstrap_failed {
                    bootstrap_attached = true;
                    let _ = writeln!(std::io::stderr(), "FLIGHTDECK_STORE_PROGRESS {{\"phase\":\"bootstrap_ready\"}}");
                    if webview.evaluate_script(&bootstrap_script(&content, &nonce, BOOTSTRAP_URL)).is_err() {
                        bootstrap_failed = true;
                        outcome = json!({"status":"Error"});
                        let _ = webview.load_html(&render(&config, &nonce, "bootstrap_error"));
                    }
                }
            }
            Event::UserEvent(value) if value["phase"].is_string() => {
                // The broker reads only this closed protocol. Native GTK stderr
                // is never forwarded to diagnostics.
                if progress_count < 8 {
                    let _ = writeln!(std::io::stderr(), "FLIGHTDECK_STORE_PROGRESS {value}");
                    progress_count += 1;
                }
                outcome = match value["phase"].as_str() {
                    Some("expired") => json!({"status":"Expired"}),
                    Some("load_timeout" | "session_timeout") => json!({"status":"Timeout"}),
                    Some("error" | "bootstrap_error") => json!({"status":"Error"}),
                    _ => outcome.clone(),
                };
                if value["phase"] == "window_ready" { host_ready = true; }
                if value["phase"] == "bootstrap_error" && !host_ready && !bootstrap_failed {
                    bootstrap_failed = true;
                    let _ = webview.load_html(&render(&config, &nonce, "bootstrap_error"));
                }
                if value["phase"] == "bootstrap_started" && !bootstrap_requested && !bootstrap_failed {
                    bootstrap_requested = true;
                    if webview.load_url(BOOTSTRAP_URL).is_err() {
                        bootstrap_failed = true;
                        outcome = json!({"status":"Error"});
                        let _ = webview.load_html(&render(&config, &nonce, "bootstrap_error"));
                    }
                }
            }
            Event::UserEvent(value) => { outcome = value; *flow = ControlFlow::Exit; }
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => *flow = ControlFlow::Exit,
            _ if !host_ready && !bootstrap_failed && started.elapsed() >= Duration::from_secs(30) => {
                bootstrap_failed = true;
                outcome = json!({"status":"Error"});
                let _ = webview.load_html(&render(&config, &nonce, "bootstrap_error"));
            }
            _ if started.elapsed() > Duration::from_secs(930) || chrono::Utc::now().timestamp() >= expiry + 30 => {
                outcome = json!({"status":"Timeout"}); *flow = ControlFlow::Exit;
            }
            _ => (),
        }
    });
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn authentic_completion_only() {
        assert!(result(&json!({"nonce":"wrong", "status":"success", "orderId":"order-1"}), "right").is_none());
        assert!(result(&json!({"nonce":"right", "status":"success"}), "right").is_none());
        assert!(result(&json!({"nonce":"right", "status":"ready"}), "right").is_none());
        assert_eq!(result(&json!({"nonce":"right", "status":"cancel"}), "right").unwrap()["status"], "Cancelled");
        assert_eq!(result(&json!({"nonce":"right", "status":"success", "orderId":"order-1"}), "right").unwrap()["status"], "Succeeded");
    }
    #[test] fn progress_and_failure_reasons_are_closed_and_nonce_bound() {
        assert!(result(&json!({"nonce":"other","phase":"checkout_ready"}),"right").is_none());
        assert!(result(&json!({"nonce":"right","phase":"private-url"}),"right").is_none());
        assert_eq!(result(&json!({"nonce":"right","phase":"checkout_ready","token":"private"}),"right").unwrap(),json!({"phase":"checkout_ready"}));
        for (reason,status) in [("expired","Expired"),("load_timeout","Timeout"),("session_timeout","Timeout"),("error","Error")] {
            assert_eq!(result(&json!({"nonce":"right","status":reason}),"right").unwrap()["status"],status);
        }
    }
    #[test] fn script_content_is_escaped() {
        let rendered = html(&json!({"xToken":"</script><script>bad()</script>"}), "nonce");
        assert!(!rendered.contains("<script>bad()"));
        assert!(rendered.contains("event.origin !== 'https://www.microsoft.com'"));
        assert!(rendered.contains("event.source !== frame.contentWindow"));
        assert!(rendered.contains("location.origin !== 'https://www.microsoft.com'"));
        assert!(!rendered.contains("__MODE__"));
    }
    #[test] fn bootstrap_requires_the_exact_main_document() {
        let script = bootstrap_script("<p>Confirmation</p>", "secret", BOOTSTRAP_URL);
        assert!(script.contains("window !== window.top"));
        assert!(script.contains("location.href !=="));
        assert!(script.contains("location.origin !=="));
        assert!(result(&json!({"nonce":"right","native_bootstrap_loaded":true}), "right").is_none());
        assert!(result(&json!({"nonce":"right","phase":"bootstrap_ready"}), "right").is_none());
        assert_eq!(result(&json!({"nonce":"right","status":"bootstrap_error"}), "right").unwrap()["status"], "Error");
    }
    #[test] fn aborted_previous_load_cannot_attach_the_checkout_host() {
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        let counter = count.clone();
        let listener = bootstrap_listener(BOOTSTRAP_URL.into(), move || counter.set(counter.get() + 1));
        listener(PageLoadEvent::Finished, BOOTSTRAP_URL.into());
        assert_eq!(count.get(), 0);
        listener(PageLoadEvent::Started, "about:blank".into());
        listener(PageLoadEvent::Finished, BOOTSTRAP_URL.into());
        assert_eq!(count.get(), 0);
        listener(PageLoadEvent::Started, BOOTSTRAP_URL.into());
        listener(PageLoadEvent::Finished, BOOTSTRAP_URL.into());
        assert_eq!(count.get(), 1);
        listener(PageLoadEvent::Started, "https://example.invalid/".into());
        listener(PageLoadEvent::Finished, BOOTSTRAP_URL.into());
        assert_eq!(count.get(), 1);
    }
}
