use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use xodus::tokens::TokenManager;

mod connection;
mod simple_context;
mod store_account;
mod store_license;
mod store_license_token;
mod store_collections;
mod store_inventory;
mod store_package_updates;
mod store_purchase;
mod store_health;
mod store_events;
mod utils;

const XML_MAGIC: u32 = 0x58445358;
const PROTO_MAGIC: u32 = 0x58445350;

#[tokio::main]
async fn main() {
    let args:Vec<_>=std::env::args_os().skip(1).collect();
    if args==[std::ffi::OsString::from("--store-check")] { store_health::run().await; return; }
    if !args.is_empty() { eprintln!("Usage: xodus-service [--store-check]"); std::process::exit(2); }
    store_events::launch();
    let filter = tracing_subscriber::EnvFilter::from_env("XODUS_LOG");
    let registry =
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().with_filter(filter));

    #[cfg(feature = "tokio_console")]
    {
        use tracing::level_filters::LevelFilter;
        use tracing_subscriber::filter::Targets;

        let console_filter = Targets::new()
            .with_target("tokio", LevelFilter::TRACE)
            .with_target("runtime", LevelFilter::TRACE);
        let console_layer = console_subscriber::spawn().with_filter(console_filter);
        registry.with(console_layer).init();
    }
    #[cfg(not(feature = "tokio_console"))]
    {
        registry.init();
    }

    xodus::secrets::init_secrets().expect("Failed to init keychain");
    let tokens = Arc::new(TokenManager::with_keychain_and_memory());
    if xodus::tokens::device::ensure_device_credentials(&reqwest::Client::new(), &tokens).await.is_err() {
        tracing::error!("Device sign-in unavailable");
        return;
    }

    let runtime_dir = utils::get_runtime_dir();
    let cancellation = CancellationToken::new();
    // M(a)C Dungeons II: private socket name (the game side sets XODUS_USER_SOCKET_SUFFIX to match).
    let socket_name = std::env::var("MACD2_SOCKET").unwrap_or_else(|_| "macd2.sock".to_string());
    let socket_path = format!("{runtime_dir}/{socket_name}");
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failure to handle ctrl_c");
        trigger.cancel();
    });
    {
        let listener = UnixListener::bind(&socket_path).expect("Unable to bind to socket");
        let mode = 0o600;
        let perms = Permissions::from_mode(mode);
        _ = tokio::fs::set_permissions(&socket_path, perms).await;
        loop {
            let accept = tokio::select! {
                r = listener.accept() => r,
                _ = cancellation.cancelled() => break,
            }
            .expect("Failed to accept");

            let token = cancellation.clone();
            let tokens = tokens.clone();
            tokio::spawn(async move {
                connection::router::route(accept.0, token, tokens).await
            });
        }
    }

    _ = tokio::fs::remove_file(socket_path).await;
    xodus::secrets::destroy_secrets();
}
