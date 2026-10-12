//! Non-interactive full-package download for the M(a)C Dungeons II launcher.
//!
//! Picks the full (non-delta) MSIXVC package of a product, downloads it in
//! parallel resumable HTTP range chunks, then extracts it with the account's
//! license through the regular streaming/extract path. Progress is printed to
//! stdout as JSON lines; URLs, key blobs and tokens are never printed.
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::commands::streaming;
use crate::package::{get_content_id, get_packages};

fn emit(line: serde_json::Value) {
    println!("{line}");
}

fn fail(stage: &str, detail: impl std::fmt::Display) -> ExitCode {
    emit(serde_json::json!({"phase": "error", "stage": stage, "detail": detail.to_string()}));
    ExitCode::FAILURE
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    workdir: String,
    destination: String,
    market: Option<String>,
) -> ExitCode {
    let content_id = match get_content_id(client, product, market.clone()).await {
        Ok(id) => id,
        Err(err) => return fail("content-id", err),
    };
    let package = match get_packages(client, tokens, content_id).await {
        Ok(p) => p,
        Err(err) => return fail("packages", err),
    };
    let Some(file) = package
        .package_files
        .iter()
        .filter(|f| f.file_name.to_ascii_lowercase().ends_with(".msixvc") && f.delta_version_id.is_none())
        .max_by_key(|f| f.file_size)
    else {
        return fail("select", "no full msixvc package");
    };
    let total = file.file_size.max(0) as u64;
    emit(serde_json::json!({"phase": "package", "version": package.version, "size": total}));

    let workdir = PathBuf::from(workdir);
    if let Err(err) = tokio::fs::create_dir_all(&workdir).await {
        return fail("workdir", err);
    }
    let safe_name: String = file
        .file_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let target = workdir.join(&safe_name);
    let partial = workdir.join(format!("{safe_name}.part"));

    let already_downloaded = std::fs::metadata(&target).is_ok_and(|m| m.len() == total);
    if !already_downloaded {
        if let Err(stage) = download(client, file, &partial, total).await {
            emit(serde_json::json!({"phase": "error", "stage": stage}));
            return ExitCode::FAILURE;
        }
        if let Err(err) = tokio::fs::rename(&partial, &target).await {
            return fail("rename", err);
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
const ATTEMPTS_PER_CHUNK: usize = 12;

/// State shared by the download workers.
struct Download {
    client: reqwest::Client,
    out: std::fs::File,
    /// One byte per chunk; set to 1 once that chunk is on disk.
    done_map: std::fs::File,
    roots: Vec<String>,
    relative_url: String,
    pending: Vec<usize>,
    total: u64,
    next: AtomicUsize,
    progress: AtomicU64,
    failed: AtomicBool,
}

/// Parallel, resumable range download. The package is split into 16 MiB
/// chunks fetched by several connections at once; `<file>.part.chunks` records
/// finished chunks so an interrupted download resumes where it stopped.
async fn download(client: &reqwest::Client, file: &PackageFile, partial: &Path, total: u64) -> Result<(), &'static str> {
    let roots: Vec<String> = file.cdn_root_paths.iter().chain(&file.background_cdn_root_paths).cloned().collect();
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
    let done_map_file = std::fs::OpenOptions::new().write(true).open(&state_path).map_err(|_| "state")?;

    let pending: Vec<usize> = (0..count).filter(|&i| done_map[i] == 0).collect();
    let finished_bytes: u64 = (0..count).filter(|&i| done_map[i] != 0).map(|i| chunk_len(i, total)).sum();
    let shared = Arc::new(Download {
        client: client.clone(),
        out,
        done_map: done_map_file,
        roots,
        relative_url: file.relative_url.clone(),
        pending,
        total,
        next: AtomicUsize::new(0),
        progress: AtomicU64::new(finished_bytes),
        failed: AtomicBool::new(false),
    });

    let reporter = {
        let shared = shared.clone();
        tokio::spawn(async move {
            loop {
                shared.report_progress();
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
    };
    let workers: Vec<_> = (0..WORKERS).map(|worker| tokio::spawn(download_worker(shared.clone(), worker))).collect();
    for w in workers {
        let _ = w.await;
    }
    reporter.abort();
    shared.report_progress();
    if shared.failed.load(Ordering::Relaxed) {
        return Err("chunk-failed");
    }
    shared.out.sync_all().map_err(|_| "flush")?;
    std::fs::remove_file(&state_path).ok();
    Ok(())
}

impl Download {
    fn report_progress(&self) {
        emit(serde_json::json!({"phase": "download", "done": self.progress.load(Ordering::Relaxed), "total": self.total}));
    }

    /// Fetches one chunk from `url`. Bytes received count towards progress
    /// as they arrive; `received` lets the caller roll them back on failure.
    async fn fetch_chunk(&self, url: &str, start: u64, len: u64, received: &mut u64) -> Option<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::RANGE, format!("bytes={}-{}", start, start + len - 1))
            .send()
            .await
            .ok()?;
        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return None;
        }
        let mut data = Vec::with_capacity(len as usize);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.ok()?;
            *received += chunk.len() as u64;
            self.progress.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            data.extend_from_slice(&chunk);
        }
        Some(data)
    }
}

/// Takes pending chunks until none are left, rotating through the CDN roots
/// on retries. Any chunk that exhausts its attempts stops every worker.
async fn download_worker(shared: Arc<Download>, worker: usize) {
    loop {
        if shared.failed.load(Ordering::Relaxed) {
            return;
        }
        let n = shared.next.fetch_add(1, Ordering::Relaxed);
        let Some(&index) = shared.pending.get(n) else { return };
        let start = index as u64 * CHUNK;
        let len = chunk_len(index, shared.total);
        let mut ok = false;
        for attempt in 0..ATTEMPTS_PER_CHUNK {
            let url = format!("{}{}", shared.roots[(worker + attempt) % shared.roots.len()], shared.relative_url);
            let mut received = 0u64;
            match shared.fetch_chunk(&url, start, len, &mut received).await {
                Some(data) if data.len() as u64 == len => {
                    if shared.out.write_all_at(&data, start).is_err() {
                        break;
                    }
                    let _ = shared.done_map.write_all_at(&[1], index as u64);
                    ok = true;
                    break;
                }
                _ => {
                    shared.progress.fetch_sub(received, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_secs(1 + attempt as u64)).await;
                }
            }
        }
        if !ok {
            shared.failed.store(true, Ordering::Relaxed);
            return;
        }
    }
}

fn chunk_len(index: usize, total: u64) -> u64 {
    let start = index as u64 * CHUNK;
    CHUNK.min(total - start)
}
