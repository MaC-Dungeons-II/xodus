//! Non-interactive full-package download for the M(a)C Dungeons II launcher.
//!
//! Picks the full (non-delta) MSIXVC package of a product, downloads it in
//! parallel resumable HTTP range chunks, then extracts it with the account's
//! license through the regular streaming/extract path. Progress is printed to
//! stdout as JSON lines; URLs, key blobs and tokens are never printed.
//!
//! Files in the work directory:
//! - `<name>.part` + `<name>.part.chunks`: the resumable download. The state
//!   file starts with a header (magic, total size, file name) followed by one
//!   byte per chunk; a header that doesn't match wipes both files.
//! - `<name>`: the finished package. Kept after an extraction that failed
//!   cleanly (e.g. a license or network error) so the next run only retries
//!   the extraction; deleted after success.
//! - `<name>.extracting`: written before extraction, removed afterwards. If it
//!   is found at startup the previous extraction died (panic, kill); a hash
//!   mismatch in the package panics, so the package is discarded and
//!   downloaded again.
//! - `.macd2-fetch.lock`: held (flock) for the whole run.
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{FutureExt, StreamExt};
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

fn fail_stage(stage: &str) -> ExitCode {
    emit(serde_json::json!({"phase": "error", "stage": stage}));
    ExitCode::FAILURE
}

/// "disk-full" for out-of-space/quota errors, `other` for anything else.
fn io_stage(err: &std::io::Error, other: &'static str) -> &'static str {
    if is_disk_full(err) { "disk-full" } else { other }
}

fn is_disk_full(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::StorageFull | ErrorKind::QuotaExceeded)
}

const LOCK_NAME: &str = ".macd2-fetch.lock";
/// Package-related suffixes cleaned up when they belong to another package.
const OWNED_SUFFIXES: [&str; 4] = [".msixvc", ".msixvc.part", ".msixvc.part.chunks", ".msixvc.extracting"];
/// Free space kept in reserve beyond the estimate.
const SPACE_MARGIN: u64 = 256 * 1024 * 1024;

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    workdir: String,
    destination: String,
    market: Option<String>,
) -> ExitCode {
    let workdir = PathBuf::from(workdir);
    if let Err(err) = tokio::fs::create_dir_all(&workdir).await {
        return fail("workdir", err);
    }
    // One run per work directory: a second instance would write the same .part.
    let _lock = match std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(workdir.join(LOCK_NAME)) {
        Ok(f) => match f.try_lock() {
            Ok(()) => f,
            Err(std::fs::TryLockError::WouldBlock) => return fail("busy", "another download is running"),
            Err(std::fs::TryLockError::Error(err)) => return fail("workdir", err),
        },
        Err(err) => return fail("workdir", err),
    };

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

    let safe_name: String = file
        .file_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let target = workdir.join(&safe_name);
    let partial = workdir.join(format!("{safe_name}.part"));
    let state_path = workdir.join(format!("{safe_name}.part.chunks"));
    let marker = workdir.join(format!("{safe_name}.extracting"));

    remove_stale(&workdir, &safe_name);
    // An extraction that died (marker left behind) may mean a corrupt package.
    if marker.exists() {
        remove_quietly(&target);
        remove_quietly(&marker);
    }
    let finished = std::fs::metadata(&target).is_ok_and(|m| m.len() == total);
    if !finished {
        remove_quietly(&target);
    }

    let destination_path = PathBuf::from(&destination);
    if !finished {
        if let Err(stage) = download(client, file, &partial, &state_path, total, &safe_name, &destination_path).await {
            return fail_stage(stage);
        }
    }

    // The marker goes first: once the final name exists, a crash at any point
    // until extraction succeeds leaves the marker behind.
    if let Err(err) = write_marker(&marker) {
        return fail_stage(io_stage(&err, "rename"));
    }
    if !finished {
        if let Err(err) = std::fs::rename(&partial, &target) {
            remove_quietly(&marker);
            return fail("rename", err);
        }
        remove_quietly(&state_path);
    }

    emit(serde_json::json!({"phase": "extract"}));
    let extraction = std::panic::AssertUnwindSafe(streaming::run(
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
    ))
    .catch_unwind()
    .await;
    let ok = matches!(extraction, Ok(code) if code == ExitCode::SUCCESS);
    // A panic (e.g. a hash mismatch) means the package can't be trusted; a
    // clean failure keeps it so the next run only retries the extraction.
    if ok || extraction.is_err() {
        remove_quietly(&target);
    }
    remove_quietly(&marker);
    if ok {
        emit(serde_json::json!({"phase": "done", "version": package.version}));
        ExitCode::SUCCESS
    } else {
        let low_space = available(&destination_path).is_some_and(|free| free < SPACE_MARGIN);
        fail_stage(if low_space { "disk-full" } else { "extract" })
    }
}

fn remove_quietly(path: &Path) {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != ErrorKind::NotFound {
            eprintln!("mac-fetch: could not remove {}: {err}", path.display());
        }
    }
}

fn write_marker(marker: &Path) -> std::io::Result<()> {
    let f = std::fs::File::create(marker)?;
    f.sync_all()
}

/// Deletes downloads, partial downloads and markers of other package names
/// (older versions) so they don't pile up in the work directory.
fn remove_stale(workdir: &Path, keep: &str) {
    let Ok(entries) = std::fs::read_dir(workdir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        let Some(suffix) = OWNED_SUFFIXES.iter().find(|s| lower.ends_with(*s)) else { continue };
        // Base package name = name without the suffix beyond ".msixvc".
        let base = &name[..name.len() - suffix.len() + ".msixvc".len()];
        if base == keep || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        remove_quietly(&entry.path());
    }
}

/// Free bytes on the volume holding `path` (or its nearest existing parent).
fn available(path: &Path) -> Option<u64> {
    let existing = path.ancestors().find(|p| p.exists())?;
    fs2::available_space(existing).ok()
}

fn device_of(path: &Path) -> Option<u64> {
    let existing = path.ancestors().find(|p| p.exists())?;
    std::fs::metadata(existing).ok().map(|m| m.dev())
}

const CHUNK: u64 = 16 * 1024 * 1024;
const WORKERS: usize = 8;
/// Attempts per chunk for failures that are not network outages (bad status,
/// mismatched range, oversized body).
const ATTEMPTS_PER_CHUNK: usize = 12;
/// How long a chunk keeps retrying through network failures (connect errors,
/// timeouts, stalls, 5xx) before the download gives up with "network".
const NETWORK_WINDOW: Duration = Duration::from_secs(6 * 60);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// No response headers or no body bytes for this long fails the attempt.
const STALL: Duration = Duration::from_secs(30);
/// A connection still trickling bytes is not a stall, but one CDN edge can
/// serve a connection at a few KB/s while the others run at full speed, and
/// the download crawls until those chunks finish. After SLOW_GRACE, an
/// attempt slower than both SLOW_FLOOR and 1/SLOW_RATIO of its fair share of
/// the current total rate is dropped and retried at once on the next CDN
/// root. A slow line slows every connection alike, so it never trips this.
const SLOW_GRACE: Duration = Duration::from_secs(15);
const SLOW_FLOOR: u64 = 1024 * 1024;
const SLOW_RATIO: u64 = 5;
/// Slow retries per chunk before it is left to finish at whatever speed.
const SLOW_RETRIES: usize = 8;
/// Chunks written between data syncs; their bitmap bytes are written only
/// after the sync, so power loss can't mark unwritten data as finished.
const SYNC_BATCH: usize = 8;

const STATE_MAGIC: &[u8; 8] = b"MACD2CK1";

const FAIL_NONE: u8 = 0;
const FAIL_NETWORK: u8 = 1;
const FAIL_CHUNK: u8 = 2;
const FAIL_DISK: u8 = 3;

/// State file header: magic, total size, name length, name.
fn state_header(total: u64, name: &str) -> Vec<u8> {
    let mut header = Vec::with_capacity(20 + name.len());
    header.extend_from_slice(STATE_MAGIC);
    header.extend_from_slice(&total.to_le_bytes());
    header.extend_from_slice(&(name.len() as u32).to_le_bytes());
    header.extend_from_slice(name.as_bytes());
    header
}

/// Why one attempt at a chunk failed.
enum AttemptError {
    /// Connect error, timeout, stall, dropped connection, 5xx/429.
    Network,
    /// Unexpected status, range or body size.
    Other,
    /// Far slower than the other connections (see SLOW_GRACE).
    Slow,
}

/// State shared by the download workers.
struct Download {
    client: reqwest::Client,
    out: std::fs::File,
    /// State file: header, then one byte per chunk set to 1 once that chunk
    /// is on disk (and synced).
    done_map: std::fs::File,
    header_len: u64,
    roots: Vec<String>,
    relative_url: String,
    pending: Vec<usize>,
    total: u64,
    next: AtomicUsize,
    progress: AtomicU64,
    /// Total download rate, bytes/s, smoothed by the progress reporter.
    rate: AtomicU64,
    failed: AtomicBool,
    failure: AtomicU8,
    /// Chunks written but not yet synced/marked.
    unflushed: Mutex<Vec<usize>>,
}

/// Parallel, resumable range download. The package is split into 16 MiB
/// chunks fetched by several connections at once; the state file records
/// finished chunks so an interrupted download resumes where it stopped.
async fn download(
    client: &reqwest::Client,
    file: &PackageFile,
    partial: &Path,
    state_path: &Path,
    total: u64,
    name: &str,
    destination: &Path,
) -> Result<(), &'static str> {
    let roots: Vec<String> = file.cdn_root_paths.iter().chain(&file.background_cdn_root_paths).cloned().collect();
    if roots.is_empty() {
        return Err("no-cdn");
    }
    let count = total.div_ceil(CHUNK) as usize;
    let header = state_header(total, name);
    let header_len = header.len();

    // Resume only from a state file whose header matches this package and a
    // .part of the full size; anything else starts over.
    let previous = std::fs::read(state_path).ok();
    let part_len = std::fs::metadata(partial).map(|m| m.len()).ok();
    let resumable = previous.as_ref().is_some_and(|s| s.len() == header_len + count && s[..header_len] == header[..])
        && part_len == Some(total);
    let done_map: Vec<u8> = match previous {
        Some(state) if resumable => state[header_len..].to_vec(),
        _ => {
            remove_quietly(partial);
            remove_quietly(state_path);
            // Header (and an empty bitmap) before the package file is allocated.
            let mut fresh = header.clone();
            fresh.resize(header_len + count, 0);
            let written = std::fs::File::create(state_path).and_then(|mut f| {
                use std::io::Write;
                f.write_all(&fresh)?;
                f.sync_all()
            });
            if let Err(err) = written {
                return Err(io_stage(&err, "state"));
            }
            vec![0; count]
        }
    };

    let pending: Vec<usize> = (0..count).filter(|&i| done_map[i] == 0).collect();
    let finished_bytes: u64 = (0..count).filter(|&i| done_map[i] != 0).map(|i| chunk_len(i, total)).sum();

    // Room for the rest of the download plus the extracted game (estimated
    // at the package size); summed when both live on the same volume.
    let remaining = total - finished_bytes;
    let work_dir = partial.parent().unwrap_or(Path::new("."));
    let enough = match (device_of(work_dir), device_of(destination)) {
        (Some(a), Some(b)) if a == b => available(work_dir).is_none_or(|free| free >= remaining + total + SPACE_MARGIN),
        _ => {
            available(work_dir).is_none_or(|free| free >= remaining + SPACE_MARGIN)
                && available(destination).is_none_or(|free| free >= total + SPACE_MARGIN)
        }
    };
    if !enough {
        return Err("disk-full");
    }

    let out = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(partial)
        .map_err(|e| io_stage(&e, "open-partial"))?;
    out.set_len(total).map_err(|e| io_stage(&e, "allocate"))?;
    let done_map_file = std::fs::OpenOptions::new().write(true).open(state_path).map_err(|e| io_stage(&e, "state"))?;

    let shared = Arc::new(Download {
        client: client.clone(),
        out,
        done_map: done_map_file,
        header_len: header_len as u64,
        roots,
        relative_url: file.relative_url.clone(),
        pending,
        total,
        next: AtomicUsize::new(0),
        progress: AtomicU64::new(finished_bytes),
        rate: AtomicU64::new(0),
        failed: AtomicBool::new(false),
        failure: AtomicU8::new(FAIL_NONE),
        unflushed: Mutex::new(Vec::new()),
    });

    let reporter = {
        let shared = shared.clone();
        tokio::spawn(async move {
            let (mut last_bytes, mut last_time) = (shared.progress.load(Ordering::Relaxed), Instant::now());
            loop {
                shared.report_progress();
                tokio::time::sleep(Duration::from_millis(500)).await;
                let (bytes, now) = (shared.progress.load(Ordering::Relaxed), Instant::now());
                let dt = now.duration_since(last_time).as_secs_f64();
                if dt > 0.0 {
                    let sample = bytes.saturating_sub(last_bytes) as f64 / dt;
                    let old = shared.rate.load(Ordering::Relaxed) as f64;
                    let smoothed = if old == 0.0 { sample } else { old * 0.9 + sample * 0.1 };
                    shared.rate.store(smoothed as u64, Ordering::Relaxed);
                }
                (last_bytes, last_time) = (bytes, now);
            }
        })
    };
    let workers: Vec<_> = (0..WORKERS).map(|worker| tokio::spawn(download_worker(shared.clone(), worker))).collect();
    for w in workers {
        if w.await.is_err() {
            shared.fail(FAIL_CHUNK);
        }
    }
    reporter.abort();
    shared.report_progress();
    // Keep whatever finished, even when stopping on a failure.
    let flushed = shared.flush_all();
    if shared.failed.load(Ordering::Relaxed) {
        return Err(match shared.failure.load(Ordering::Relaxed) {
            FAIL_NETWORK => "network",
            FAIL_DISK => "disk-full",
            _ => "chunk-failed",
        });
    }
    flushed.map_err(|e| io_stage(&e, "flush"))?;
    Ok(())
}

impl Download {
    fn report_progress(&self) {
        emit(serde_json::json!({"phase": "download", "done": self.progress.load(Ordering::Relaxed), "total": self.total}));
    }

    /// Stops every worker; the first reason recorded wins.
    fn fail(&self, reason: u8) {
        let _ = self.failure.compare_exchange(FAIL_NONE, reason, Ordering::Relaxed, Ordering::Relaxed);
        self.failed.store(true, Ordering::Relaxed);
    }

    /// Syncs the package data, then marks `chunks` finished in the bitmap.
    fn flush(&self, chunks: &[usize]) -> std::io::Result<()> {
        if chunks.is_empty() {
            return Ok(());
        }
        self.out.sync_data()?;
        for &index in chunks {
            self.done_map.write_all_at(&[1], self.header_len + index as u64)?;
        }
        Ok(())
    }

    /// Records a written chunk; every SYNC_BATCH chunks are synced and marked.
    fn chunk_written(&self, index: usize) -> std::io::Result<()> {
        let batch = {
            let mut unflushed = self.unflushed.lock().unwrap_or_else(|p| p.into_inner());
            unflushed.push(index);
            if unflushed.len() < SYNC_BATCH {
                return Ok(());
            }
            std::mem::take(&mut *unflushed)
        };
        self.flush(&batch)
    }

    fn flush_all(&self) -> std::io::Result<()> {
        let batch = std::mem::take(&mut *self.unflushed.lock().unwrap_or_else(|p| p.into_inner()));
        self.flush(&batch)?;
        self.out.sync_all()
    }

    /// Fetches one chunk from `url`. Bytes received count towards progress
    /// as they arrive; `received` lets the caller roll them back on failure.
    async fn fetch_chunk(
        &self,
        url: &str,
        start: u64,
        len: u64,
        received: &mut u64,
        check_slow: bool,
    ) -> Result<Vec<u8>, AttemptError> {
        let end = start + len - 1;
        let request = self.client.get(url).header(reqwest::header::RANGE, format!("bytes={start}-{end}")).send();
        let response = match tokio::time::timeout(STALL, request).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => return Err(AttemptError::Network),
        };
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AttemptError::Network);
        }
        if status != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(AttemptError::Other);
        }
        let range_ok = response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| content_range_matches(v, start, end, self.total));
        if !range_ok {
            return Err(AttemptError::Other);
        }
        let mut data = Vec::with_capacity(len as usize);
        let mut stream = response.bytes_stream();
        let begun = Instant::now();
        loop {
            if check_slow && self.too_slow(data.len() as u64, begun.elapsed()) {
                return Err(AttemptError::Slow);
            }
            let chunk = match tokio::time::timeout(STALL, stream.next()).await {
                Ok(Some(Ok(chunk))) => chunk,
                Ok(None) => break,
                Ok(Some(Err(_))) | Err(_) => return Err(AttemptError::Network),
            };
            if data.len() as u64 + chunk.len() as u64 > len {
                return Err(AttemptError::Other);
            }
            *received += chunk.len() as u64;
            self.progress.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            data.extend_from_slice(&chunk);
        }
        if data.len() as u64 != len {
            // Connection closed early.
            return Err(AttemptError::Network);
        }
        Ok(data)
    }
}

impl Download {
    /// This attempt, `bytes` in `elapsed`, is far behind the other connections.
    fn too_slow(&self, bytes: u64, elapsed: Duration) -> bool {
        if elapsed < SLOW_GRACE {
            return false;
        }
        let own = (bytes as f64 / elapsed.as_secs_f64()) as u64;
        let fair = self.rate.load(Ordering::Relaxed) / WORKERS as u64;
        own < SLOW_FLOOR && own.saturating_mul(SLOW_RATIO) < fair
    }
}

/// `bytes <start>-<end>/<total or *>` must describe exactly the requested range.
fn content_range_matches(value: &str, start: u64, end: u64, total: u64) -> bool {
    let Some(rest) = value.trim().strip_prefix("bytes ") else { return false };
    let Some((range, size)) = rest.split_once('/') else { return false };
    let Some((a, b)) = range.split_once('-') else { return false };
    let size_ok = size.trim() == "*" || size.trim().parse::<u64>() == Ok(total);
    a.trim().parse::<u64>() == Ok(start) && b.trim().parse::<u64>() == Ok(end) && size_ok
}

/// Takes pending chunks until none are left, rotating through the CDN roots
/// on retries. Network failures are retried with exponential backoff for up
/// to NETWORK_WINDOW; other failures for ATTEMPTS_PER_CHUNK attempts. A chunk
/// that gives up, or a failed write, stops every worker.
async fn download_worker(shared: Arc<Download>, worker: usize) {
    loop {
        if shared.failed.load(Ordering::Relaxed) {
            return;
        }
        let n = shared.next.fetch_add(1, Ordering::Relaxed);
        let Some(&index) = shared.pending.get(n) else { return };
        let start = index as u64 * CHUNK;
        let len = chunk_len(index, shared.total);
        let mut first_failure: Option<Instant> = None;
        let mut other_failures = 0usize;
        let mut consecutive = 0u32;
        let mut attempt = 0usize;
        let mut slow_retries = 0usize;
        loop {
            if shared.failed.load(Ordering::Relaxed) {
                return;
            }
            let url = format!("{}{}", shared.roots[(worker + attempt) % shared.roots.len()], shared.relative_url);
            attempt += 1;
            let mut received = 0u64;
            let check_slow = slow_retries < SLOW_RETRIES;
            let error = match shared.fetch_chunk(&url, start, len, &mut received, check_slow).await {
                Ok(data) => {
                    let written = shared.out.write_all_at(&data, start).and_then(|()| shared.chunk_written(index));
                    if let Err(err) = written {
                        shared.fail(if is_disk_full(&err) { FAIL_DISK } else { FAIL_CHUNK });
                        return;
                    }
                    break;
                }
                Err(error) => error,
            };
            shared.progress.fetch_sub(received, Ordering::Relaxed);
            if matches!(error, AttemptError::Slow) {
                // not a failure: straight to the next CDN root
                slow_retries += 1;
                continue;
            }
            let since = *first_failure.get_or_insert_with(Instant::now);
            let give_up = match error {
                AttemptError::Network => since.elapsed() >= NETWORK_WINDOW,
                AttemptError::Other => {
                    other_failures += 1;
                    other_failures >= ATTEMPTS_PER_CHUNK
                }
                AttemptError::Slow => unreachable!(),
            };
            if give_up {
                shared.fail(if matches!(error, AttemptError::Network) { FAIL_NETWORK } else { FAIL_CHUNK });
                return;
            }
            let backoff = Duration::from_secs(1u64 << consecutive.min(5)).min(MAX_BACKOFF);
            consecutive += 1;
            tokio::time::sleep(backoff).await;
        }
    }
}

fn chunk_len(index: usize, total: u64) -> u64 {
    let start = index as u64 * CHUNK;
    CHUNK.min(total - start)
}
