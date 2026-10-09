//! Non-interactive full-package download for the M(a)C Dungeons II launcher.
//!
//! Picks the full (non-delta) MSIXVC package of a product, downloads it
//! sequentially with HTTP range resume, then extracts it with the account's
//! license through the regular streaming/extract path. Progress is printed to
//! stdout as JSON lines; URLs, key blobs and tokens are never printed.
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use futures_util::StreamExt;
use xodus::tokens::TokenManager;

use crate::commands::streaming;
use crate::package::{get_content_id, get_packages};

fn emit(line: serde_json::Value) {
    println!("{line}");
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    workdir: String,
    destination: String,
    market: Option<String>,
) -> ExitCode {
    let content_id = match get_content_id(client, product.clone(), market.clone()).await {
        Ok(id) => id,
        Err(err) => {
            emit(serde_json::json!({"phase": "error", "stage": "content-id", "detail": err.to_string()}));
            return ExitCode::FAILURE;
        }
    };
    let package = match get_packages(client, tokens, content_id.clone()).await {
        Ok(p) => p,
        Err(err) => {
            emit(serde_json::json!({"phase": "error", "stage": "packages", "detail": err.to_string()}));
            return ExitCode::FAILURE;
        }
    };
    let Some(file) = package
        .package_files
        .iter()
        .filter(|f| f.file_name.to_ascii_lowercase().ends_with(".msixvc") && f.delta_version_id.is_none())
        .max_by_key(|f| f.file_size)
        .cloned()
    else {
        emit(serde_json::json!({"phase": "error", "stage": "select", "detail": "no full msixvc package"}));
        return ExitCode::FAILURE;
    };
    let total = file.file_size.max(0) as u64;
    emit(serde_json::json!({"phase": "package", "version": package.version, "size": total}));

    let workdir = PathBuf::from(workdir);
    if let Err(err) = tokio::fs::create_dir_all(&workdir).await {
        emit(serde_json::json!({"phase": "error", "stage": "workdir", "detail": err.to_string()}));
        return ExitCode::FAILURE;
    }
    let safe_name: String = file
        .file_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let target = workdir.join(&safe_name);
    let partial = workdir.join(format!("{safe_name}.part"));

    if !(target.exists() && std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0) == total) {
        if let Err(stage) = download(client, &file, &partial, total).await {
            emit(serde_json::json!({"phase": "error", "stage": stage}));
            return ExitCode::FAILURE;
        }
        if let Err(err) = tokio::fs::rename(&partial, &target).await {
            emit(serde_json::json!({"phase": "error", "stage": "rename", "detail": err.to_string()}));
            return ExitCode::FAILURE;
        }
    }

    emit(serde_json::json!({"phase": "extract"}));
    let code = streaming::run(
        client,
        tokens,
        format!("file://{}", target.display()),
        destination,
        false,
        None,
        market,
        false,
        None,
        None,
    )
    .await;
    if code == ExitCode::SUCCESS {
        tokio::fs::remove_file(&target).await.ok();
        emit(serde_json::json!({"phase": "done", "version": package.version}));
    } else {
        emit(serde_json::json!({"phase": "error", "stage": "extract"}));
    }
    code
}

const CHUNK: u64 = 16 * 1024 * 1024;
const WORKERS: usize = 8;

/// Parallel, resumable range download. The package is split into 16 MiB
/// chunks fetched by several connections at once; `<file>.chunks` records
/// finished chunks so an interrupted download resumes where it stopped.
async fn download(
    client: &reqwest::Client,
    file: &xodus::models::packagespc::PackageFile,
    partial: &Path,
    total: u64,
) -> Result<(), &'static str> {
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let roots: Vec<String> = file.cdn_root_paths.iter().chain(file.background_cdn_root_paths.iter()).cloned().collect();
    if roots.is_empty() {
        return Err("no-cdn");
    }
    let count = total.div_ceil(CHUNK) as usize;
    let state_path = partial.with_extension("part.chunks");

    // Bitmap of finished chunks (one byte each). A legacy sequential .part
    // without a bitmap counts its complete leading chunks as finished.
    let previous_len = std::fs::metadata(partial).map(|m| m.len()).unwrap_or(0);
    let mut done_map = std::fs::read(&state_path).unwrap_or_default();
    if done_map.len() != count {
        let legacy = if previous_len <= total { (previous_len / CHUNK) as usize } else { 0 };
        done_map = (0..count).map(|i| (i < legacy) as u8).collect();
    }
    let out = std::fs::OpenOptions::new().create(true).write(true).read(true).open(partial).map_err(|_| "open-partial")?;
    out.set_len(total).map_err(|_| "allocate")?;
    std::fs::write(&state_path, &done_map).map_err(|_| "state")?;
    let out = Arc::new(out);
    let state = Arc::new(Mutex::new((std::fs::OpenOptions::new().write(true).open(&state_path).map_err(|_| "state")?, done_map.clone())));

    let pending: Vec<usize> = (0..count).filter(|&i| done_map[i] == 0).collect();
    let finished_bytes: u64 = (0..count).filter(|&i| done_map[i] != 0).map(|i| chunk_len(i, total)).sum();
    let progress = Arc::new(AtomicU64::new(finished_bytes));
    let next = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let pending = Arc::new(pending);
    let url_tail = Arc::new(file.relative_url.clone());
    let roots = Arc::new(roots);

    let reporter = {
        let progress = progress.clone();
        tokio::spawn(async move {
            loop {
                emit(serde_json::json!({"phase": "download", "done": progress.load(Ordering::Relaxed), "total": total}));
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
    };

    let mut workers = Vec::new();
    for worker in 0..WORKERS {
        let (client, out, state, progress, next, failed, pending, url_tail, roots) = (
            client.clone(), out.clone(), state.clone(), progress.clone(), next.clone(), failed.clone(),
            pending.clone(), url_tail.clone(), roots.clone(),
        );
        workers.push(tokio::spawn(async move {
            loop {
                if failed.load(Ordering::Relaxed) { return; }
                let n = next.fetch_add(1, Ordering::Relaxed);
                let Some(&index) = pending.get(n) else { return };
                let start = index as u64 * CHUNK;
                let len = chunk_len(index, total);
                let mut ok = false;
                for attempt in 0..12usize {
                    let url = format!("{}{}", roots[(worker + attempt) % roots.len()], url_tail);
                    let mut received = 0u64;
                    let result: Result<Vec<u8>, ()> = async {
                        let response = client.get(&url)
                            .header(reqwest::header::RANGE, format!("bytes={}-{}", start, start + len - 1))
                            .send().await.map_err(|_| ())?;
                        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT { return Err(()); }
                        let mut data = Vec::with_capacity(len as usize);
                        let mut stream = response.bytes_stream();
                        while let Some(chunk) = stream.next().await {
                            let chunk = chunk.map_err(|_| ())?;
                            received += chunk.len() as u64;
                            progress.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                            data.extend_from_slice(&chunk);
                        }
                        Ok(data)
                    }.await;
                    match result {
                        Ok(data) if data.len() as u64 == len => {
                            if out.write_all_at(&data, start).is_err() { break; }
                            let mut st = state.lock().unwrap();
                            st.1[index] = 1;
                            let _ = st.0.write_all_at(&[1], index as u64);
                            ok = true;
                            break;
                        }
                        _ => {
                            progress.fetch_sub(received, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_secs(1 + attempt as u64)).await;
                        }
                    }
                }
                if !ok { failed.store(true, Ordering::Relaxed); return; }
            }
        }));
    }
    for w in workers { let _ = w.await; }
    reporter.abort();
    emit(serde_json::json!({"phase": "download", "done": progress.load(Ordering::Relaxed), "total": total}));
    if failed.load(Ordering::Relaxed) {
        return Err("chunk-failed");
    }
    out.sync_all().map_err(|_| "flush")?;
    std::fs::remove_file(&state_path).ok();
    Ok(())
}

fn chunk_len(index: usize, total: u64) -> u64 {
    let start = index as u64 * CHUNK;
    CHUNK.min(total - start)
}
