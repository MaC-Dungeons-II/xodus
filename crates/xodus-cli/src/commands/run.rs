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
/// Failures are logged and the entry skipped.
fn mirror_into_view(src: &Path, dst: &Path, root: &Path, decrypted: &HashSet<String>) {
    let entries = match std::fs::read_dir(src) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("macd2 view: cannot list {}: {err}", src.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(".xodus") {
            continue;
        }
        let path = entry.path();
        let target = dst.join(&name);
        let Ok(rel) = path.strip_prefix(root) else { continue };
        let rel = rel.to_string_lossy().to_ascii_lowercase();
        let link = |path: &Path, target: &Path| {
            if let Err(err) = std::os::unix::fs::symlink(path, target) {
                eprintln!("macd2 view: cannot link {}: {err}", target.display());
            }
        };
        if path.is_dir() {
            let dir_prefix = format!("{rel}/");
            if decrypted.iter().any(|d| d.starts_with(&dir_prefix)) {
                if let Err(err) = std::fs::create_dir_all(&target) {
                    eprintln!("macd2 view: cannot create {}: {err}", target.display());
                    continue;
                }
                mirror_into_view(&path, &target, root, decrypted);
            } else if !target.exists() {
                link(&path, &target);
            }
        } else if !decrypted.contains(&rel) && !target.exists() {
            link(&path, &target);
        }
    }
}

/// RAM disk holding the MACD2_VIEW game view. Dropping it unmounts and
/// detaches the disk (also on error returns and panics). While it exists a
/// marker `$TMPDIR/macd2-view-disks/<pid>` records the device so that a run
/// killed with SIGKILL is cleaned up by the next run (`detach_stale_views`).
#[cfg(target_os = "macos")]
struct ViewDisk {
    device: String,
    mount: Option<tempfile::TempDir>,
    marker: std::path::PathBuf,
}

#[cfg(target_os = "macos")]
fn view_marker_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("macd2-view-disks")
}

#[cfg(target_os = "macos")]
fn detach_view_disk(device: &str, mount: Option<&Path>) -> bool {
    use std::process::{Command, Stdio};
    if let Some(mount) = mount {
        let unmounted = Command::new("/sbin/umount").arg("-f").arg(mount).stdout(Stdio::null()).status();
        if !unmounted.is_ok_and(|s| s.success()) {
            eprintln!("macd2 view: umount {} failed", mount.display());
        }
    }
    let detached = Command::new("/usr/bin/hdiutil")
        .args(["detach", "-force", device])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !detached {
        eprintln!("macd2 view: detaching {device} failed");
    }
    detached
}

#[cfg(target_os = "macos")]
impl ViewDisk {
    async fn create(size: u64) -> Result<Self, String> {
        std::fs::create_dir_all(view_marker_dir()).map_err(|e| format!("marker directory: {e}"))?;
        let marker = view_marker_dir().join(std::process::id().to_string());
        let attach = Command::new("/usr/bin/hdiutil")
            .arg("attach")
            .arg("-nomount")
            .arg(format!("ram://{}", size.div_ceil(256)))
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| format!("hdiutil attach: {e}"))?;
        let device = String::from_utf8_lossy(&attach.stdout).trim().to_string();
        if !attach.status.success() || !device.starts_with("/dev/disk") || device.contains(char::is_whitespace) {
            return Err("hdiutil attach failed".into());
        }
        // From here on Drop detaches the disk.
        let mut disk = ViewDisk { device, mount: None, marker };
        disk.write_marker(None)?;

        let formatted = Command::new("/sbin/newfs_hfs")
            .arg("-v")
            .arg(uuid::Uuid::new_v4().to_string())
            .arg(&disk.device)
            .stdout(std::process::Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success());
        if !formatted {
            return Err("newfs_hfs failed".into());
        }
        let mount_dir = tempdir().map_err(|e| format!("mount point: {e}"))?;
        let mounted = Command::new("/sbin/mount")
            .args(["-t", "hfs", "-o", "nobrowse"])
            .arg(&disk.device)
            .arg(mount_dir.path())
            .status()
            .await
            .is_ok_and(|s| s.success());
        if !mounted {
            return Err("mount failed".into());
        }
        disk.write_marker(Some(mount_dir.path()))?;
        disk.mount = Some(mount_dir);
        Ok(disk)
    }

    fn write_marker(&self, mount: Option<&Path>) -> Result<(), String> {
        // Canonical, so it compares equal to what `hdiutil info` reports
        // (/var/folders is /private/var/folders).
        let mount = mount
            .map(|m| std::fs::canonicalize(m).unwrap_or_else(|_| m.to_path_buf()).to_string_lossy().into_owned())
            .unwrap_or_default();
        std::fs::write(&self.marker, format!("{}\n{}\n", self.device, mount)).map_err(|e| format!("marker: {e}"))
    }

    fn path(&self) -> &Path {
        self.mount.as_ref().map(|m| m.path()).unwrap_or(Path::new("/nonexistent"))
    }
}

#[cfg(target_os = "macos")]
impl Drop for ViewDisk {
    fn drop(&mut self) {
        let mount = self.mount.take();
        if detach_view_disk(&self.device, mount.as_ref().map(|m| m.path())) {
            let _ = std::fs::remove_file(&self.marker);
        }
        // The (now empty) mount point directory is removed by TempDir.
        drop(mount);
    }
}

/// Mount point (empty if unmounted) of `device` if `hdiutil info` lists it
/// as a RAM disk image; None if it is not one (or no longer attached).
#[cfg(target_os = "macos")]
fn ram_disk_mount(device: &str) -> Option<String> {
    let info = std::process::Command::new("/usr/bin/hdiutil")
        .arg("info")
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let info = String::from_utf8_lossy(&info.stdout);
    info.split("================================================").find_map(|section| {
        let is_ram = section.lines().any(|l| l.starts_with("image-path") && l.contains(": ram://"));
        if !is_ram {
            return None;
        }
        section.lines().find_map(|l| {
            let mut fields = l.split('\t');
            (fields.next()? == device).then(|| fields.nth(1).unwrap_or("").trim().to_string())
        })
    })
}

#[cfg(target_os = "macos")]
fn same_path(a: &str, b: &str) -> bool {
    a == b || std::fs::canonicalize(a).is_ok_and(|ca| std::fs::canonicalize(b).is_ok_and(|cb| ca == cb))
}

/// Detaches view RAM disks left behind by runs that no longer exist
/// (SIGKILL, crash). Disks of live runs are left alone, and a device is only
/// touched if it is still a RAM disk mounted where the marker says.
#[cfg(target_os = "macos")]
fn detach_stale_views() {
    let Ok(entries) = std::fs::read_dir(view_marker_dir()) else { return };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        if pid <= 0 || pid as u32 == std::process::id() {
            continue;
        }
        // ESRCH means the recording run is gone; anything else (alive, EPERM) keeps it.
        if kill(Pid::from_raw(pid), None) != Err(nix::errno::Errno::ESRCH) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else { continue };
        let mut lines = content.lines();
        let device = lines.next().unwrap_or("").trim().to_string();
        let recorded_mount = lines.next().unwrap_or("").trim().to_string();
        let removed = match ram_disk_mount(&device) {
            None => true,
            Some(mount) if mount.is_empty() || same_path(&mount, &recorded_mount) => {
                let mount = (!mount.is_empty()).then(|| std::path::PathBuf::from(&mount));
                let detached = detach_view_disk(&device, mount.as_deref());
                if detached {
                    if let Some(mount) = &mount {
                        let _ = std::fs::remove_dir(mount);
                    }
                }
                detached
            }
            // Same device number, different volume: not ours any more.
            Some(_) => true,
        };
        if removed {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// M(a)C Dungeons II: builds a game view inside a RAM disk where encrypted
/// executables are real decrypted files and everything else is a symlink to
/// the installation, then runs Wine on it. Titles that re-read their own image
/// from disk (integrity checks) then see the same plaintext Windows' package
/// view provides. Decrypted bytes only ever live on the RAM disk, which is
/// detached when this returns or unwinds; SIGINT/SIGTERM are forwarded to Wine.
#[cfg(target_os = "macos")]
async fn run_view(
    xvd: &XvdFile,
    lfiles: &HashMap<String, SegmentFile>,
    out_absolute: &Path,
    full_key: [u8; 32],
    wine: String,
    exe: Option<String>,
    game_args: &[String],
) -> Result<ExitCode, String> {
    use tokio::signal::unix::{SignalKind, signal};

    detach_stale_views();
    let disk_size: u64 = lfiles
        .values()
        .filter(|f| f.keep_encrypted)
        .map(|f| f.length + 4 * PAGE_SIZE as u64)
        .sum();
    if disk_size == 0 {
        return Err("no encrypted files to decrypt".into());
    }
    let mut sigint = signal(SignalKind::interrupt()).map_err(|e| format!("signal handler: {e}"))?;
    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| format!("signal handler: {e}"))?;
    let disk = ViewDisk::create(disk_size).await?;

    let view = disk.path().join("view");
    let mut decrypted = HashSet::new();
    for (path, segment) in lfiles {
        if !segment.keep_encrypted {
            continue;
        }
        let rel = path.trim_start_matches('\\').replace('\\', "/");
        decrypted.insert(rel.to_ascii_lowercase());
        let dest = view.join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("view dir for {rel}: {e}"))?;
        }
        let mut plain = File::from_std(std::fs::File::create(&dest).map_err(|e| format!("view file {rel}: {e}"))?);
        let mut source = File::open(out_absolute.join(&rel)).await.map_err(|e| format!("open {rel}: {e}"))?;
        if xvd.mount_mem_fd(&mut source, &mut plain, segment, full_key, |_, _| {}).await.is_err() {
            return Err(format!("decrypting {rel} failed"));
        }
    }
    std::fs::create_dir_all(&view).map_err(|e| format!("view dir: {e}"))?;
    mirror_into_view(out_absolute, &view, out_absolute, &decrypted);
    let entry_rel = exe
        .as_deref()
        .map(|e| e.trim_start_matches(['\\', '/']).replace('\\', "/"))
        .unwrap_or_default();
    let entry = view.join(&entry_rel);
    let mut wn = Command::new(wine)
        .arg(&entry)
        .args(game_args)
        .current_dir(entry.parent().unwrap_or(&view))
        .spawn()
        .map_err(|e| format!("starting wine: {e}"))?;
    let pid = wn.id().map(|p| Pid::from_raw(p as i32));
    let forward = |sig: Signal| {
        if let Some(pid) = pid {
            let _ = kill(pid, sig);
        }
    };
    let status = loop {
        tokio::select! {
            status = wn.wait() => break status,
            _ = sigint.recv() => forward(Signal::SIGINT),
            _ = sigterm.recv() => {
                forward(Signal::SIGTERM);
                // Give Wine a moment to exit, then make sure the disk can go.
                match tokio::time::timeout(std::time::Duration::from_secs(15), wn.wait()).await {
                    Ok(status) => break status,
                    Err(_) => {
                        let _ = wn.start_kill();
                        break wn.wait().await;
                    }
                }
            }
        }
    };
    let status = status.map_err(|e| format!("waiting for wine: {e}"))?;
    drop(disk);
    Ok(ExitCode::from(crate::process_status::shell_exit_code(status)))
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

    #[cfg(target_os = "macos")]
    if std::env::var_os("MACD2_VIEW").is_some() {
        return match run_view(&xvd, &lfiles, &out_absolute, *full_key, wine, exe, &game_args).await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("macd2 view: {err}");
                ExitCode::FAILURE
            }
        };
    }

    let (cleanup, mount_dir) = prepare(&lfiles).await;

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
