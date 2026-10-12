use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, IntoRawFd};
use std::path::Path;
use std::process::ExitCode;

use msixvc::layout::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;
use xodus::tokens::TokenManager;

use crate::license::get_license;

#[cfg(target_os = "linux")]
fn make_temp_file(_folder: &str) -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file(folder: &str) -> std::io::Result<std::fs::File> {
    if folder.is_empty() {
        tempfile()
    } else {
        tempfile_in(folder)
    }
}

/// Fills `dst` with symlinks to `src` (relative to `root`), skipping the
/// `.xodus*` bookkeeping entries and the lowercase relative paths in `decrypted`
/// that already exist in `dst` as plaintext files. Directories containing such
/// files are recreated and mirrored entry by entry instead of being linked.
fn mirror_into_view(src: &Path, dst: &Path, root: &Path, decrypted: &HashSet<String>) {
    let Ok(entries) = std::fs::read_dir(src) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(".xodus") {
            continue;
        }
        let path = entry.path();
        let target = dst.join(&name);
        let rel = path.strip_prefix(root).unwrap().to_string_lossy().to_ascii_lowercase();
        if path.is_dir() {
            let dir_prefix = format!("{rel}/");
            if decrypted.iter().any(|d| d.starts_with(&dir_prefix)) {
                std::fs::create_dir_all(&target).ok();
                mirror_into_view(&path, &target, root, decrypted);
            } else if !target.exists() {
                std::os::unix::fs::symlink(&path, &target).ok();
            }
        } else if !decrypted.contains(&rel) && !target.exists() {
            std::os::unix::fs::symlink(&path, &target).ok();
        }
    }
}

#[cfg(target_os = "macos")]
async fn prepare(lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    let disk_size: u64 = lfiles
        .iter()
        .filter(|f| f.1.keep_encrypted)
        .map(|f| f.1.length + 4 * PAGE_SIZE as u64)
        .reduce(|o, s| o + s)
        .unwrap();

    let device_s = String::from_utf8(
        Command::new("/usr/bin/hdiutil")
            .arg("attach")
            .arg("-nomount")
            .arg(format!("ram://{}", disk_size.div_ceil(256)))
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .unwrap();

    let device = device_s.trim();

    let vol = uuid::Uuid::new_v4().to_string();

    let fmt = Command::new("/sbin/newfs_hfs")
        .arg("-v")
        .arg(vol)
        .arg(device)
        .status()
        .await
        .unwrap();
    assert!(fmt.success());

    let mount_dir_obj = tempdir().unwrap();
    let mount_dir = mount_dir_obj.path().to_str().unwrap();

    let mnt = Command::new("/sbin/mount")
        .arg("-t")
        .arg("hfs")
        .arg("-o")
        .arg("nobrowse")
        .arg("-v")
        .arg(device)
        .arg(mount_dir)
        .status()
        .await
        .unwrap();
    assert!(mnt.success());
    let mount_dir_cl = mount_dir.to_string();
    let device_cl = device.to_string();
    (
        async move || {
            let mnt = Command::new("/sbin/umount")
                .arg("-f")
                .arg(mount_dir_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());

            let mnt = Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg("-force")
                .arg(&device_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());
        },
        mount_dir.to_owned(),
    )
}

#[cfg(not(target_os = "macos"))]
async fn prepare(_lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    (async || {}, "".to_owned())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    wine: String,
    exe: Option<String>,
    market: Option<String>,
    game_args: Vec<String>,
) -> ExitCode {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let out_absolute = std::fs::canonicalize(out).unwrap();
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .unwrap();

    let xvd = XvdFile::parse(&mut file).await.expect("no err");

    let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
            lfiles = sfiles;
        }
    }

    // Classic files
    if lfiles.is_empty() {
        let sfiles = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
            .expect("ok");
        for (n, sfile) in &sfiles {
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return ExitCode::FAILURE;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return ExitCode::FAILURE;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let mut fds = vec![];

    let (cleanup, mount_dir) = prepare(&lfiles).await;

    // M(a)C Dungeons II: on macOS, build a game view inside the RAM disk where
    // encrypted executables are real decrypted files and everything else is a
    // symlink to the installation. Titles that re-read their own image from
    // disk (integrity checks) then see the same plaintext Windows' package view
    // provides. Decrypted bytes only ever live on the RAM disk.
    if cfg!(target_os = "macos") && std::env::var_os("MACD2_VIEW").is_some() {
        let view = Path::new(&mount_dir).join("view");
        let mut decrypted = HashSet::new();
        for (path, segment) in &lfiles {
            if !segment.keep_encrypted {
                continue;
            }
            let rel = path.trim_start_matches('\\').replace('\\', "/");
            decrypted.insert(rel.to_ascii_lowercase());
            let dest = view.join(&rel);
            std::fs::create_dir_all(dest.parent().unwrap()).expect("view dir");
            let mut plain = File::from_std(std::fs::File::create(&dest).expect("view file"));
            let mut source = File::open(out_absolute.join(&rel)).await.unwrap();
            xvd.mount_mem_fd(&mut source, &mut plain, segment, *full_key, |_, _| {}).await.unwrap();
        }
        std::fs::create_dir_all(&view).ok();
        mirror_into_view(&out_absolute, &view, &out_absolute, &decrypted);
        let entry_rel = exe
            .as_deref()
            .map(|e| e.trim_start_matches(['\\', '/']).replace('\\', "/"))
            .unwrap_or_default();
        let entry = view.join(&entry_rel);
        let mut wn = Command::new(wine)
            .arg(&entry)
            .args(&game_args)
            .current_dir(entry.parent().unwrap_or(&view))
            .spawn()
            .unwrap();
        let pid = wn.id().unwrap();
        ctrlc::set_handler(move || {
            if pid > 0 {
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
            }
        })
        .expect("failed to install Ctrl+C handler");
        let status = wn.wait().await.unwrap();
        cleanup().await;
        return ExitCode::from(crate::process_status::shell_exit_code(status));
    }

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = File::from_std(make_temp_file(&mount_dir).unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await
            .unwrap();

        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, stdf.into_raw_fd()));
    }

    let mut env_value = String::new();
    let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');

    let mut nt_entry = None;
    let normalize_exe = |s: &str| s.trim_start_matches(['\\', '/']).replace('/', "\\").to_ascii_lowercase();

    for fd in fds {
        if !env_value.is_empty() {
            env_value.push('|');
        }

        let nt_suffix = fd.0.trim_start_matches('\\');
        let nt_path = format!("\\??\\Z:{}\\{}", nt_prefix, nt_suffix);
        if let Some(exe) = &exe {
            if normalize_exe(exe) == normalize_exe(fd.0) {
                nt_entry = Some(nt_path)
            }
        } else if nt_entry.is_none() {
            nt_entry = Some(nt_path)
        }

        env_value.push_str(&format!("{}:\\??\\Z:{}\\{}", fd.1, nt_prefix, nt_suffix))
    }

    let Some(nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        return ExitCode::FAILURE;
    };

    let mut wn = Command::new(wine)
        .arg(nt_entry)
        .args(&game_args)
        .env("WINE_DLL_FILE_MAP", env_value)
        .spawn()
        .unwrap();

    let pid = wn.id().unwrap();

    ctrlc::set_handler(move || {
        if pid > 0 {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
        }
    })
    .expect("failed to install Ctrl+C handler");

    let status = wn.wait().await.unwrap();

    cleanup().await;

    ExitCode::from(crate::process_status::shell_exit_code(status))
}
