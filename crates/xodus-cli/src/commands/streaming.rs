#[path = "streaming_progress.rs"]
mod streaming_progress;
#[path = "streaming_resume.rs"]
mod streaming_resume;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::ExitCode;
use std::vec;
use streaming_progress::Progress;
use streaming_resume::Resume;
use tokio::io::AsyncWriteExt;

use fs2::available_space;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::{get_content_id, get_packages};

struct Job {
    name: String,
    content: SegmentFile,
}

enum ProgressEvent {
    Started { id: usize, name: String, total: u64 },
    Advanced { id: usize, delta: u64 },
    Finished { id: usize },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    resume_files: bool,
    expect_package: Option<String>,
    progress_fd: Option<i32>,
) -> ExitCode {
    if progress_fd.is_some() && !resume_files {
        return ExitCode::FAILURE;
    }
    let Ok(machine_progress) = Progress::new(progress_fd) else {
        eprintln!("Invalid progress pipe");
        return ExitCode::FAILURE;
    };
    if resume_files && source.contains("://") {
        eprintln!("Resume requires an authenticated Store product or content ID");
        return ExitCode::FAILURE;
    }
    if resume_files && !user_credentials_current(tokens) {
        // Machine contract for the parent installer: ordinary interactive login
        // is required. Never print the credential or attempt to fabricate it.
        return ExitCode::from(77);
    }
    if expect_package.as_ref().is_some_and(|s| {
        s.len() != 64
            || !s
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    }) {
        return ExitCode::FAILURE;
    }
    let mut package_identity = None;
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    let success = if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = match File::open(fsrc).await {
            Ok(f) => f,
            Err(err) => {
                eprintln!("could not open {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = match f.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                eprintln!("could not read metadata for {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            resume_files,
            package_identity,
            f,
            l,
            &source,
            &tx,
            rx,
            &machine_progress,
        )
        .await
    } else {
        let vurl = if source.starts_with("http://") || source.starts_with("https://") {
            source
        } else {
            let content_id = if Uuid::try_parse(&source).is_err() {
                let content_id_task = get_content_id(client, source, market.clone()).await;
                let Ok(content_id) = content_id_task else {
                    let Err(err) = content_id_task else {
                        eprintln!("Unknown Error");
                        return ExitCode::FAILURE;
                    };
                    eprintln!("{}", err);
                    return ExitCode::FAILURE;
                };
                content_id
            } else {
                source
            };
            let package_result = get_packages(client, tokens, content_id.clone()).await;
            let Ok(package) = package_result else {
                let Err(err) = package_result else {
                    eprintln!("Unknown Error");
                    return ExitCode::FAILURE;
                };
                eprintln!("{}", err);
                return ExitCode::FAILURE;
            };
            let Some(file) = package
                .package_files
                .iter()
                .find(|p| p.file_name.ends_with(".msixvc"))
            else {
                eprintln!("No .msixvc file found");
                return ExitCode::FAILURE;
            };
            if resume_files {
                package_identity = authenticated_package_identity(&package, file);
                if package_identity.is_none() {
                    eprintln!("Package version identity required for resume is missing");
                    return ExitCode::FAILURE;
                }
            }
            if !expected_revision_matches(expect_package.as_deref(), package_identity.as_deref()) {
                // Never mix a newly selected package with an earlier approved update.
                return ExitCode::from(78);
            }
            format!(
                "{}{}",
                file.cdn_root_paths.first().unwrap(),
                file.relative_url
            )
        };
        let url = &vurl;
        let mut pos = 0;
        let http_file = streaming::HttpRead::open(
            client.clone(),
            url,
            Some(|c, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id: usize::MAX,
                        delta: c - pos,
                    })
                    .is_ok()
                {
                    pos = c;
                }
            }),
        )
        .await
        .expect("ok");
        let l = http_file.len();

        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            resume_files,
            package_identity,
            http_file,
            l,
            url,
            &tx,
            rx,
            &machine_progress,
        )
        .await
    };

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run_cli_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    resume_files: bool,
    package_identity: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    mut rx: Receiver<ProgressEvent>,
    machine_progress: &Progress,
) -> bool
where
    Reader: AsyncRead + Unpin,
{
    tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l).with_style(
            ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
            .progress_chars("#>-")
        ));

        total_progess.set_message("Initializing");
        let mut bars: HashMap<usize, ProgressBar> = HashMap::new();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Started { id, name, total } => {
                    let cur_progess = multi_progress.add(ProgressBar::new(total).with_style(
                        ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
                        .progress_chars("#>-")
                    ));
                    cur_progess.set_message(name);
                    bars.insert(id, cur_progess);
                }
                ProgressEvent::Advanced { id, delta } => {
                    if let Some(bar) = bars.get(&id) {
                        bar.inc(delta);
                    }
                    total_progess.inc(delta);
                }
                ProgressEvent::Finished { id } => {
                    if let Some(bar) = bars.remove(&id) {
                        bar.finish_and_clear();
                    }
                }
                ProgressEvent::UpdateRemaining { name, total } => {
                    total_progess.set_message(name);
                    total_progess.set_length(total_progess.position() + total);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
            }
        }

        total_progess.abandon();
    });
    run_reader(
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        resume_files,
        package_identity,
        reader,
        l,
        url,
        tx,
        machine_progress,
    )
    .await
}

async fn run_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    resume_files: bool,
    package_identity: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    machine_progress: &Progress,
) -> bool
where
    Reader: AsyncRead + Unpin,
{
    let original_out = Path::new(&destination);
    std::fs::create_dir_all(original_out).expect("ok");
    let resume =
        resume_files.then(|| Resume::open(original_out).expect("resume destination rejected"));

    let anchored = resume.as_ref().map(Resume::root_path);
    let out: &Path = anchored.as_deref().unwrap_or(original_out);

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = if let Some(r) = &resume {
        let (cache_reader, cache_writer) = r.prepare_cache().expect("unsafe metadata cache");
        streaming::PrefixCacheFile::with_cache(
            reader,
            l,
            File::from_std(cache_reader),
            File::from_std(cache_writer),
        )
        .expect("cache setup failed")
    } else {
        streaming::PrefixCacheFile::new(reader, l, cache_path.clone())
            .await
            .expect("no err")
    };
    let remote_xvd = XvdFile::parse(&mut remote_file).await.expect("no err");
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = remote_xvd
        .parse_user_package_files(&mut remote_file)
        .await
        .expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = remote_xvd
                .parse_segment_metadata(&mut remote_file, v)
                .await
                .expect("ok");
            rfiles = sfiles;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty())
            .await
            .expect("ok");
        rfiles.extend(sfiles);
    }

    let mut complete = HashSet::new();
    if let Some(r) = &resume {
        let mut names = HashSet::new();
        let mut entries: Vec<_> = rfiles.iter().collect();
        entries.sort_by_key(|(name, _)| *name);
        let mut identity = Sha256::new();
        // Content IDs and file layouts can survive a version change, especially
        // for files lacking data_hashs. Bind the authenticated package revision
        // too, while deliberately excluding rotating CDN URLs and key blobs.
        identity.update(
            package_identity
                .as_ref()
                .expect("missing authenticated package identity")
                .as_bytes(),
        );
        identity.update(remote_xvd.content_id().as_bytes());
        identity.update(l.to_le_bytes());
        for (name, file) in &entries {
            let normal = streaming_resume::normalized(name).expect("unsafe package path");
            assert!(names.insert(normal), "duplicate package path");
            identity.update((name.len() as u64).to_le_bytes());
            identity.update(name.as_bytes());
            identity.update(file.offset.to_le_bytes());
            identity.update(file.length.to_le_bytes());
            identity.update([u8::from(file.keep_encrypted)]);
            identity.update((file.data_hashs.len() as u64).to_le_bytes());
            for hash in &file.data_hashs {
                identity.update(hash);
            }
        }
        let fingerprint: String = identity
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        r.bind(&fingerprint)
            .expect("resume package changed or journal invalid");
        for (name, file) in entries {
            if r.completed(name, output_length(file))
                .expect("unsafe resume file")
            {
                complete.insert(name.clone());
            }
        }
    }

    if resume_files {
        let total_bytes = rfiles
            .values()
            .try_fold(0u64, |sum, file| sum.checked_add(output_length(file)))
            .expect("total output size overflow");
        let verified_bytes = rfiles
            .iter()
            .filter(|(name, _)| complete.contains(*name))
            .try_fold(0u64, |sum, (_, file)| sum.checked_add(output_length(file)))
            .expect("verified output size overflow");
        machine_progress.configure(
            total_bytes,
            rfiles.len() as u64,
            verified_bytes,
            complete.len() as u64,
        );
    }

    let file = if resume_files {
        None
    } else {
        OpenOptions::new()
            .read(true)
            .open(final_path.to_owned())
            .await
            .ok()
    };

    if let Some(mut file) = file {
        let xvd = XvdFile::parse(&mut file).await.expect("no err");

        let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
                lfiles = sfiles;
            }
        }

        if let Ok(sfiles) = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
        {
            lfiles.extend(sfiles);
        }
    }

    let license = get_license(
        client,
        tokens,
        remote_xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return false;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return false;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return false;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let total_size = rfiles
        .iter()
        .filter(|(k, v1)| {
            if resume_files {
                return !complete.contains(*k);
            }
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(_, v)| output_length(v))
        .sum();

    let required_free_space = total_size;
    let available_free_space = match available_space(out) {
        Ok(space) => space,
        Err(err) => {
            eprintln!(
                "failed to determine available space for {}: {}",
                out.display(),
                err
            );
            return false;
        }
    };

    if available_free_space < required_free_space {
        eprintln!(
            "not enough free disk space on {}: need {} bytes, have {} bytes (files: {})",
            out.display(),
            required_free_space,
            available_free_space,
            total_size
        );
        return false;
    }

    tx.send(ProgressEvent::UpdateRemaining {
        name: "Downloading".to_owned(),
        total: total_size,
    })
    .await
    .ok();

    let remote_xvd_ref = &remote_xvd;
    let resume_ref = resume.as_ref();
    stream::iter(
        rfiles
            .iter()
            .filter(|(k, v1)| {
                if resume_files {
                    return !complete.contains(*k);
                }
                if let Some(v2) = lfiles.get(*k) {
                    v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
                } else {
                    true
                }
            })
            .map(|(n, v)| Job {
                name: n.clone(),
                content: SegmentFile {
                    offset: v.offset,
                    length: v.length,
                    data_hashs: if resume_files {
                        v.data_hashs.clone()
                    } else {
                        vec![]
                    },
                    keep_encrypted: v.keep_encrypted,
                },
            })
            .enumerate(),
    )
    .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
        let tx = tx.clone();
        let client = client.clone();
        async move {
            let mut fout = if let Some(r) = resume_ref {
                File::from_std(r.begin(&job.name).expect("resume target rejected"))
            } else {
                let target_file = out.join(job.name.replace("\\", "/"));
                if let Some(folder) = target_file.parent() {
                    std::fs::create_dir_all(folder).expect("ok");
                }
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(target_file)
                    .await
                    .expect("ok")
            };
            let mut lp = 0;
            machine_progress.start(id, output_length(&job.content));

            let progress = |pos, _| {
                machine_progress.advance(id, pos);
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id,
                        delta: pos - lp,
                    })
                    .is_ok()
                {
                    lp = pos;
                }
            };
            let path = job.name.to_owned();
            let shown = if path.chars().count() > 30 {
                format!(
                    "...{}",
                    path.chars()
                        .skip(path.chars().count() - 27)
                        .collect::<String>()
                )
            } else {
                path.clone()
            };
            tx.send(ProgressEvent::Started {
                id,
                name: shown,
                total: job.content.length,
            })
            .await
            .ok();

            if let Some(fpath) = url.strip_prefix("file://") {
                let mut i = File::open(&fpath).await.unwrap();
                remote_xvd_ref
                    .extract_file(&mut i, &mut fout, &job.content, *full_key, progress)
                    .await
                    .expect("msg");
            } else {
                remote_xvd_ref
                    .download_file_http(&client, url, &mut fout, &job.content, *full_key, progress)
                    .await
                    .expect("msg");
            }
            fout.flush().await.expect("file flush failed");
            if let Some(r) = resume_ref {
                fout.sync_all().await.expect("file sync failed");
                r.commit(
                    &job.name,
                    output_length(&job.content),
                    fout.into_std().await,
                )
                .expect("resume commit failed");
                machine_progress.finish(id);
            }
            tx.send(ProgressEvent::Finished { id }).await.ok();
        }
    })
    .await;

    if let Some(r) = &resume {
        remote_file
            .sync_cache()
            .await
            .expect("metadata sync failed");
        let expected: Vec<_> = rfiles
            .iter()
            .map(|(name, file)| (name.clone(), output_length(file)))
            .collect();
        r.finish_verified(&expected)
            .expect("resume finalization failed");
    } else {
        std::fs::remove_file(&final_path).ok();
        std::fs::rename(&cache_path, &final_path).expect("ok");
    }
    true
}

fn output_length(file: &SegmentFile) -> u64 {
    if file.keep_encrypted {
        file.length.checked_add(4095).expect("file size overflow") / 4096 * 4096
    } else {
        file.length
    }
}

pub(crate) fn user_credentials_current(tokens: &TokenManager) -> bool {
    let Ok(xodus::models::secrets::Token::Legacy(token)) = tokens.get_user_sts_token() else {
        return false;
    };
    chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)
        .is_ok_and(|expiry| expiry.timestamp() > chrono::Utc::now().timestamp() + 60)
}

#[cfg(test)]
mod resume_contract_tests {
    use super::*;
    #[test]
    fn encrypted_output_retains_whole_pages_and_plaintext_keeps_exact_size() {
        for (length, expected) in [
            (0, 0),
            (1, 4096),
            (4096, 4096),
            (4097, 8192),
            (195570688, 195571712),
        ] {
            let f = SegmentFile {
                offset: 0,
                length,
                data_hashs: vec![],
                keep_encrypted: true,
            };
            assert_eq!(output_length(&f), expected);
            let f = SegmentFile {
                keep_encrypted: false,
                ..f
            };
            assert_eq!(output_length(&f), length);
        }
    }
    #[test]
    fn missing_user_sts_requires_login_without_reading_real_account() {
        assert!(!user_credentials_current(&TokenManager::with_memory()));
    }
}

fn four_part_version(value: &str) -> Option<String> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    parts
        .iter()
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse::<u16>().ok().map(|v| v.to_string())
        })
        .collect::<Option<Vec<_>>>()
        .map(|v| v.join("."))
}
fn canonical_guid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string().eq_ignore_ascii_case(value))
}

/// The package service can use a build-qualified revision as all three
/// version fields. Keep that complete authenticated revision in the identity;
/// only this exact syntax may project to the executable's four-part version.
pub(crate) fn package_game_version(
    package: &xodus::models::packagespc::PackageDetails,
    file: &xodus::models::packagespc::PackageFile,
) -> Option<String> {
    if let Some(version) = four_part_version(&package.version) {
        return (canonical_guid(&package.version_id) && canonical_guid(&file.version_id))
            .then_some(version);
    }
    let (version, build) = package.version.rsplit_once('.')?;
    if !canonical_guid(build)
        || package.version_id != package.version
        || file.version_id != package.version
    {
        return None;
    }
    four_part_version(version)
}

pub(crate) fn authenticated_package_identity(
    package: &xodus::models::packagespc::PackageDetails,
    file: &xodus::models::packagespc::PackageFile,
) -> Option<String> {
    package_game_version(package, file)?;
    let compound = package.version.split('.').count() == 5;
    if file.file_hash.len() > 4096
        || file.file_hash.chars().any(char::is_control)
        || (file.file_hash.is_empty() && !compound)
    {
        return None;
    }
    let fields = [
        &package.content_id,
        &package.version_id,
        &package.version,
        &file.content_id,
        &file.version_id,
        &file.file_name,
    ];
    if !package.package_found
        || file.file_size <= 0
        || fields
            .iter()
            .any(|v| v.is_empty() || v.len() > 4096 || v.chars().any(char::is_control))
    {
        return None;
    }
    let mut identity = Sha256::new();
    for field in fields {
        identity.update((field.len() as u64).to_le_bytes());
        identity.update(field.as_bytes());
    }
    identity.update((file.file_hash.len() as u64).to_le_bytes());
    identity.update(file.file_hash.as_bytes());
    identity.update(file.file_size.to_le_bytes());
    Some(
        identity
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}
#[cfg(test)]
mod package_revision_tests {
    use super::*;
    use xodus::models::packagespc::{PackageDetails, PackageFile};
    fn package() -> PackageDetails {
        PackageDetails {
            package_found: true,
            content_id: "11111111-1111-4111-8111-111111111111".into(),
            version_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),
            version: "1.0.0.0".into(),
            hash_of_hashes: None,
            update_predownload: false,
            availability_date: String::new(),
            package_files: vec![PackageFile {
                content_id: "11111111-1111-4111-8111-111111111111".into(),
                version_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),
                file_name: "synthetic.msixvc".into(),
                file_size: 4096,
                file_hash: "synthetic-public-package-hash-a".into(),
                key_blob: "synthetic-secret-never-in-journal".into(),
                cdn_root_paths: vec!["https://invalid.example/old".into()],
                background_cdn_root_paths: vec![],
                relative_url: "?synthetic-signed-old".into(),
                update_type: 0,
                delta_version_id: None,
                license_usage_type: 0,
                modified_date: String::new(),
            }],
        }
    }
    #[test]
    fn new_revision_with_identical_file_layout_is_not_reused() {
        let a = package();
        let first = authenticated_package_identity(&a, &a.package_files[0]).unwrap();
        let mut b = a.clone();
        b.version_id = "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee".into();
        b.version = "2.0.0.0".into();
        let second = authenticated_package_identity(&b, &b.package_files[0]).unwrap();
        assert_ne!(first, second);
        let d = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let r = Resume::open(d.path()).unwrap();
        r.bind(&first).unwrap();
        assert!(r.bind(&second).is_err());
        b = a.clone();
        b.package_files[0].file_hash = "different-payload-same-size".into();
        assert_ne!(
            first,
            authenticated_package_identity(&b, &b.package_files[0]).unwrap()
        );
    }
    #[test]
    fn refreshed_signed_access_keeps_revision_and_missing_identity_is_rejected() {
        let a = package();
        let first = authenticated_package_identity(&a, &a.package_files[0]).unwrap();
        let mut b = a.clone();
        b.package_files[0].cdn_root_paths = vec!["https://invalid.example/new".into()];
        b.package_files[0].relative_url = "?synthetic-signed-new".into();
        b.package_files[0].key_blob = "synthetic-secret-rotated".into();
        assert_eq!(
            first,
            authenticated_package_identity(&b, &b.package_files[0]).unwrap()
        );
        b.package_files[0].file_hash.clear();
        assert!(authenticated_package_identity(&b, &b.package_files[0]).is_none());
    }
}

fn expected_revision_matches(expected: Option<&str>, actual: Option<&str>) -> bool {
    expected.is_none() || expected == actual
}

#[cfg(test)]
mod expected_revision_tests {
    use super::*;
    #[test]
    fn expected_package_never_accepts_new_or_missing_identity() {
        assert!(expected_revision_matches(None, None));
        assert!(expected_revision_matches(Some("a"), Some("a")));
        assert!(!expected_revision_matches(Some("a"), Some("b")));
        assert!(!expected_revision_matches(Some("a"), None));
    }
}
