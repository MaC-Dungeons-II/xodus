// SPDX-License-Identifier: GPL-3.0-only
//! Local renderer check: a human confirms visible content. Loading a DOM alone
//! is insufficient evidence that GTK actually displays the webview.
use serde_json::json;
use std::{io::Write, time::{Duration, Instant}};
use tao::{dpi::LogicalSize,event::{Event,WindowEvent},event_loop::{ControlFlow,EventLoopBuilder},platform::run_return::EventLoopExtRunReturn,window::WindowBuilder};
use wry::WebViewBuilder;
pub fn run(language:&str)->std::process::ExitCode {
    let status=show(language).unwrap_or("error");
    let value=json!({"stage":"window","state":if status=="visible"{"passed"}else if status=="cancelled"{"cancelled"}else{"failed"},"code":status});
    let _=writeln!(std::io::stdout(),"{value}");std::process::ExitCode::SUCCESS
}
pub(crate) fn html(language:&str,nonce:&str)->String {
    let de=language=="de";
    let (title,description,confirm,cancel)=if de {
        ("Store-Fenster prüfen","Wenn du diesen Text und beide Schaltflächen siehst, bestätige die Anzeige. Dieses Fenster ist lokal; es öffnet keine Kaufseite.","Anzeige funktioniert","Abbrechen")
    } else {("Check Store window","If you can see this text and both buttons, confirm the display. This window is local; it does not open a purchase page.","Display works","Cancel")};
    format!(r#"<!doctype html><html lang="{}"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; base-uri 'none'"><title>{title}</title><style>body{{background:#fff;color:#171717;font:18px system-ui;padding:32px;line-height:1.5}}h1{{font-size:26px}}button{{font:inherit;padding:12px;margin:10px 8px 0 0}}button:focus-visible{{outline:3px solid #006fba}}</style><h1>{title}</h1><p>{description}</p><button id="confirm">{confirm}</button><button id="cancel">{cancel}</button><script nonce="{nonce}">for(const [id,result] of [['confirm','visible'],['cancel','cancelled']])document.getElementById(id).onclick=()=>window.ipc.postMessage(JSON.stringify({{nonce:'{nonce}',result}}));</script></html>"#,if de{"de"}else{"en"})
}
fn show(language:&str)->Result<&'static str,()> {
    let nonce=uuid::Uuid::new_v4().simple().to_string();
    let html=html(language,&nonce);
    let title=if language=="de"{"Store-Fenster prüfen"}else{"Check Store window"};
    let mut events=EventLoopBuilder::<String>::with_user_event().build();
    let window=WindowBuilder::new().with_title(title).with_inner_size(LogicalSize::new(580.,360.)).build(&events).map_err(|_|())?;
    let proxy=events.create_proxy();
    let builder=WebViewBuilder::new().with_incognito(true).with_devtools(false).with_html(html)
        .with_navigation_handler(|url|url=="about:blank"||url.starts_with("http://tauri.localhost"))
        .with_ipc_handler(move|r| {if r.body().len()>256{return;}
            if let Ok(v)=serde_json::from_str::<serde_json::Value>(r.body()) {
                if v["nonce"]==nonce {if let Some(s)=v["result"].as_str().filter(|s|["visible","cancelled"].contains(s)){let _=proxy.send_event(s.into());}}
            }
        });
    let _view=crate::store_purchase::attach_webview(&window,builder)?;
    let started=Instant::now();let mut outcome="cancelled";
    events.run_return(|event,_,flow|{
        *flow=ControlFlow::WaitUntil(Instant::now()+Duration::from_millis(250));
        match event {
            Event::UserEvent(v)=>{outcome=if v=="visible"{"visible"}else{"cancelled"};*flow=ControlFlow::Exit;},
            Event::WindowEvent{event:WindowEvent::CloseRequested,..}=>*flow=ControlFlow::Exit,
            _ if started.elapsed()>Duration::from_secs(90)=>{outcome="timeout";*flow=ControlFlow::Exit;},_=>(),
        }
    });Ok(outcome)
}
