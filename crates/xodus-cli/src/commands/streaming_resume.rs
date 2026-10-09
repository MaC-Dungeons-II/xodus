// SPDX-License-Identifier: GPL-3.0-only
//! Restart-safe completed-file receipts, not byte-level or credential storage.
//! A receipt is published only after the file and directory entry are durable.
//! All mutations use anchored directory descriptors and reject symlink traversal.
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use fs2::FileExt;
use nix::libc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const JOURNAL: &str = ".xodus-resume";
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid streaming resume data")
}
fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| invalid())
}
fn open_at(dir: &File, name: &str, flags: i32) -> io::Result<File> {
    let name = cstr(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    if !(m.is_file() || (flags & libc::O_DIRECTORY != 0 && m.is_dir())) {
        return Err(invalid());
    }
    if m.is_file() && m.nlink() != 1 {
        return Err(invalid());
    }
    Ok(file)
}
fn directory(dir: &File, name: &str, create: bool) -> io::Result<File> {
    if create {
        let c = cstr(name)?;
        if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        } else {
            dir.sync_all()?;
        }
    }
    open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)
}
fn unlink(dir: &File, name: &str) -> io::Result<()> {
    let c = cstr(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    Ok(())
}
fn rename(src: &File, from: &str, dst: &File, to: &str) -> io::Result<()> {
    let from = cstr(from)?;
    let to = cstr(to)?;
    if unsafe { libc::renameat(src.as_raw_fd(), from.as_ptr(), dst.as_raw_fd(), to.as_ptr()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    dst.sync_all()?;
    Ok(())
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
pub fn hash_bytes(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}
fn file_hash(file: &mut File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex(hash.finalize()))
}
pub fn normalized(name: &str) -> io::Result<String> {
    let name = name.replace('\\', "/");
    if name.len() > 4096
        || name.starts_with(".xodus-")
        || name.contains(':')
        || name.chars().any(char::is_control)
        || name
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == "..")
    {
        return Err(invalid());
    }
    Ok(name)
}
fn read_json(dir: &File, name: &str) -> io::Result<Value> {
    let file = open_at(dir, name, libc::O_RDONLY)?;
    if file.metadata()?.len() > 8192 {
        return Err(invalid());
    }
    serde_json::from_reader(file).map_err(|_| invalid())
}
fn atomic_json(dir: &File, name: &str, value: &Value) -> io::Result<()> {
    let tmp = format!("{name}.new");
    // A stale temporary is never followed, reused, or accepted as a receipt.
    unlink(dir, &tmp)?;
    let mut f = open_at(dir, &tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
    serde_json::to_writer(&mut f, value)?;
    f.flush()?;
    f.sync_all()?;
    rename(dir, &tmp, dir, name)
}

pub struct Resume {
    root: File,
    journal: File,
    _lock: File,
    cache_identity: std::sync::OnceLock<(u64, u64)>,
}
impl Drop for Resume {
    fn drop(&mut self) {
        // Explicit unlock also releases a transient fork-inherited description;
        // waiting for every copy to close can otherwise delay the next session.
        let _ = FileExt::unlock(&self._lock);
    }
}
impl Resume {
    /// Open only a private destination owned by this user. No auth data is read.
    pub fn open(root: &Path) -> io::Result<Self> {
        let c = CString::new(root.as_os_str().as_bytes()).map_err(|_| invalid())?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let root = unsafe { File::from_raw_fd(fd) };
        let metadata = root.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(invalid());
        }
        let journal = directory(&root, JOURNAL, true)?;
        let jm = journal.metadata()?;
        if jm.uid() != metadata.uid() || jm.mode() & 0o077 != 0 {
            return Err(invalid());
        }
        let lock = open_at(&journal, "lock", libc::O_RDWR | libc::O_CREAT)?;
        FileExt::try_lock_exclusive(&lock)?;
        Ok(Self {
            root,
            journal,
            _lock: lock,
            cache_identity: std::sync::OnceLock::new(),
        })
    }
    pub fn bind(&self, fingerprint: &str) -> io::Result<()> {
        let expected = json!({"format":1,"package_sha256":fingerprint});
        match read_json(&self.journal, "package.json") {
            Ok(actual) if actual == expected => Ok(()),
            Ok(_) => Err(invalid()), // Updated package: don't mix versions silently.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                atomic_json(&self.journal, "package.json", &expected)
            }
            Err(e) => Err(e),
        }
    }
    fn target_parent(&self, name: &str, create: bool) -> io::Result<(File, String)> {
        let name = normalized(name)?;
        let mut parts: Vec<_> = name.split('/').collect();
        let leaf = parts.pop().ok_or_else(invalid)?.to_string();
        let mut dir = self.root.try_clone()?;
        for part in parts {
            dir = directory(&dir, part, create)?;
        }
        Ok((dir, leaf))
    }
    pub fn completed(&self, name: &str, expected_len: u64) -> io::Result<bool> {
        let name = normalized(name)?;
        let receipt = format!("{}.json", hash_bytes(name.as_bytes()));
        let data = match read_json(&self.journal, &receipt) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::InvalidData
                ) =>
            {
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        if data["name"] != name
            || data["length"] != expected_len
            || data["sha256"].as_str().is_none()
        {
            return Ok(false);
        }
        let (dir, leaf) = match self.target_parent(&name, false) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let mut file = match open_at(&dir, &leaf, libc::O_RDONLY) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(file.metadata()?.len() == expected_len
            && file_hash(&mut file)? == data["sha256"].as_str().unwrap())
    }
    pub fn begin(&self, name: &str) -> io::Result<File> {
        let name = normalized(name)?;
        // Validate/create parents before any transfer. A leaf symlink is rejected
        // too; rename would replace it safely, but would conceal an unsafe target.
        let (dir, leaf) = self.target_parent(&name, true)?;
        match open_at(&dir, &leaf, libc::O_RDONLY) {
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let partial = format!("{}.part", hash_bytes(name.as_bytes()));
        unlink(&self.journal, &partial)?;
        open_at(
            &self.journal,
            &partial,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )
    }
    pub fn commit(&self, name: &str, expected_len: u64, mut file: File) -> io::Result<()> {
        let name = normalized(name)?;
        file.sync_all()?;
        if file.metadata()?.len() != expected_len {
            return Err(invalid());
        }
        let digest = file_hash(&mut file)?;
        let id = hash_bytes(name.as_bytes());
        let partial = format!("{id}.part");
        let on_disk = open_at(&self.journal, &partial, libc::O_RDONLY)?;
        if (on_disk.metadata()?.dev(), on_disk.metadata()?.ino())
            != (file.metadata()?.dev(), file.metadata()?.ino())
        {
            return Err(invalid());
        }
        let (dir, leaf) = self.target_parent(&name, false)?;
        rename(&self.journal, &partial, &dir, &leaf)?;
        atomic_json(
            &self.journal,
            &format!("{id}.json"),
            &json!({"name":name,"length":expected_len,"sha256":digest}),
        )
    }
    /// The metadata cache is intentionally fetched afresh on each invocation.
    /// An anchored /proc fd avoids reopening a caller-controlled root path.
    pub fn root_path(&self) -> std::path::PathBuf {
        format!("/proc/self/fd/{}", self.root.as_raw_fd()).into()
    }
    pub fn prepare_cache(&self) -> io::Result<(File, File)> {
        for name in [".xodus-streaming-tmp.msixvc", ".xodus-streaming.msixvc"] {
            match open_at(&self.root, name, libc::O_RDONLY) {
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        unlink(&self.root, ".xodus-streaming-tmp.msixvc")?;
        let writer = open_at(
            &self.root,
            ".xodus-streaming-tmp.msixvc",
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )?;
        let reader = open_at(&self.root, ".xodus-streaming-tmp.msixvc", libc::O_RDONLY)?;
        let identity = (writer.metadata()?.dev(), writer.metadata()?.ino());
        if identity != (reader.metadata()?.dev(), reader.metadata()?.ino()) {
            return Err(invalid());
        }
        self.cache_identity.set(identity).map_err(|_| invalid())?;
        Ok((reader, writer))
    }
    /// Seal the complete expected file set, never a directory scan. Receipts
    /// come only from committed downloads or freshly rehashed resume skips.
    /// Python can later detect removed files/receipts without creating a baseline.
    pub fn finish_verified(&self, expected: &[(String, u64)]) -> io::Result<()> {
        if expected.is_empty() || expected.len() > 100_000 {
            return Err(invalid());
        }
        let package = read_json(&self.journal, "package.json")?;
        let mut files = Vec::with_capacity(expected.len());
        let mut seen = std::collections::HashSet::new();
        for (name, length) in expected {
            let name = normalized(name)?;
            if !seen.insert(name.clone()) {
                return Err(invalid());
            }
            let receipt = read_json(
                &self.journal,
                &format!("{}.json", hash_bytes(name.as_bytes())),
            )?;
            let digest = receipt["sha256"].as_str().ok_or_else(invalid)?;
            if receipt["name"] != name
                || receipt["length"] != *length
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid());
            }
            files.push(json!({"name":name, "length":length, "sha256":digest}));
        }
        self.finish()?;
        // The launch path reads this finalized prefix cache without modifying
        // it. Hash its actual length, not the remote package's logical size.
        let mut cache = open_at(&self.root, ".xodus-streaming.msixvc", libc::O_RDONLY)?;
        files.push(json!({"name":".xodus-streaming.msixvc",
            "length":cache.metadata()?.len(), "sha256":file_hash(&mut cache)?}));
        files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let index = json!({
            "format": 1, "source": "xodus-completed-download-v1",
            "package_sha256": package["package_sha256"], "files": files
        });
        if serde_json::to_vec(&index)?.len() > 32 * 1024 * 1024 {
            return Err(invalid());
        }
        atomic_json(&self.journal, "integrity.json", &index)
    }

    pub fn finish(&self) -> io::Result<()> {
        let cache = open_at(&self.root, ".xodus-streaming-tmp.msixvc", libc::O_RDONLY)?;
        if self.cache_identity.get() != Some(&(cache.metadata()?.dev(), cache.metadata()?.ino())) {
            return Err(invalid());
        }
        cache.sync_all()?;
        rename(
            &self.root,
            ".xodus-streaming-tmp.msixvc",
            &self.root,
            ".xodus-streaming.msixvc",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn root() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn committed_file_survives_restart_and_corruption_is_not_reused() {
        let d = root();
        {
            let r = Resume::open(d.path()).unwrap();
            r.bind("same package").unwrap();
            let mut f = r.begin("dir\\file").unwrap();
            f.write_all(b"complete").unwrap();
            r.commit("dir/file", 8, f).unwrap();
        }
        let r = Resume::open(d.path()).unwrap();
        r.bind("same package").unwrap();
        assert!(r.completed("dir/file", 8).unwrap());
        assert!(!r.completed("dir/file", 9).unwrap());
        std::fs::write(d.path().join("dir/file"), b"changed!").unwrap();
        assert!(!r.completed("dir/file", 8).unwrap());
        assert!(r.bind("new package").is_err());
    }
    #[test]
    fn incomplete_and_missing_files_are_never_complete() {
        let d = root();
        {
            let r = Resume::open(d.path()).unwrap();
            r.bind("a").unwrap();
            let mut f = r.begin("file").unwrap();
            f.write_all(b"part").unwrap();
            assert!(r.commit("file", 8, f).is_err());
        }
        let r = Resume::open(d.path()).unwrap();
        assert!(!r.completed("file", 8).unwrap());
        assert_eq!(r.begin("file").unwrap().metadata().unwrap().len(), 0);
        let mut f = r.begin("file").unwrap();
        f.write_all(b"ok").unwrap();
        r.commit("file", 2, f).unwrap();
        std::fs::remove_file(d.path().join("file")).unwrap();
        assert!(!r.completed("file", 2).unwrap());
    }
    #[test]
    fn symlink_hardlink_fifo_and_traversal_rejected() {
        let d = root();
        let outside = root();
        let r = Resume::open(d.path()).unwrap();
        for name in [
            "../escape",
            "/absolute",
            "x/../escape",
            "C:\\file",
            ".xodus-resume/x",
            "a//b",
            "",
        ] {
            assert!(r.begin(name).is_err(), "{name}");
        }
        symlink(outside.path(), d.path().join("dir")).unwrap();
        assert!(r.begin("dir/escape").is_err());
        symlink(outside.path().join("file"), d.path().join("file")).unwrap();
        assert!(r.begin("file").is_err());
        std::fs::write(outside.path().join("original"), b"outside").unwrap();
        std::fs::hard_link(outside.path().join("original"), d.path().join("hard")).unwrap();
        assert!(r.begin("hard").is_err());
        let fifo = cstr(d.path().join("fifo").to_str().unwrap()).unwrap();
        unsafe {
            libc::mkfifo(fifo.as_ptr(), 0o600);
        }
        assert!(r.begin("fifo").is_err());
        assert!(!outside.path().join("escape").exists());
    }
    #[test]
    fn journal_is_private_locked_and_corrupt_receipt_cannot_skip() {
        let d = root();
        let r = Resume::open(d.path()).unwrap();
        r.bind("p").unwrap();
        assert!(Resume::open(d.path()).is_err());
        let f = r.begin("empty").unwrap();
        r.commit("empty", 0, f).unwrap();
        assert!(r.completed("empty", 0).unwrap());
        let receipt = d
            .path()
            .join(JOURNAL)
            .join(format!("{}.json", hash_bytes(b"empty")));
        assert_eq!(receipt.metadata().unwrap().mode() & 0o077, 0);
        std::fs::write(receipt, b"broken").unwrap();
        assert!(!r.completed("empty", 0).unwrap());
    }
    #[test]
    fn journal_and_metadata_symlinks_rejected() {
        let d = root();
        let outside = root();
        symlink(outside.path(), d.path().join(JOURNAL)).unwrap();
        assert!(Resume::open(d.path()).is_err());
        let d = root();
        let r = Resume::open(d.path()).unwrap();
        symlink(
            outside.path().join("victim"),
            d.path().join(".xodus-streaming-tmp.msixvc"),
        )
        .unwrap();
        assert!(r.prepare_cache().is_err());
    }
    #[test]
    fn commit_before_receipt_crash_redownloads_safely() {
        let d = root();
        let r = Resume::open(d.path()).unwrap();
        let mut f = r.begin("x").unwrap();
        f.write_all(b"complete").unwrap();
        f.sync_all().unwrap();
        rename(
            &r.journal,
            &format!("{}.part", hash_bytes(b"x")),
            &r.root,
            "x",
        )
        .unwrap();
        assert!(!r.completed("x", 8).unwrap());
        let mut f = r.begin("x").unwrap();
        f.write_all(b"complete").unwrap();
        r.commit("x", 8, f).unwrap();
        assert!(r.completed("x", 8).unwrap());
    }
    #[test]
    fn sealed_index_has_exact_expected_set_and_committed_hashes() {
        let d = root();
        let r = Resume::open(d.path()).unwrap();
        r.bind(&"a".repeat(64)).unwrap();
        let (_reader, mut cache) = r.prepare_cache().unwrap();
        cache.write_all(b"metadata").unwrap();
        for (name, bytes) in [
            ("encrypted.exe", b"\0\xff\0".as_slice()),
            ("empty", b"".as_slice()),
        ] {
            let mut f = r.begin(name).unwrap();
            f.write_all(bytes).unwrap();
            r.commit(name, bytes.len() as u64, f).unwrap();
        }
        r.finish_verified(&[("encrypted.exe".into(), 3), ("empty".into(), 0)])
            .unwrap();
        let index = read_json(&r.journal, "integrity.json").unwrap();
        assert_eq!(index["files"].as_array().unwrap().len(), 3);
        assert_eq!(index["files"][2]["sha256"], hash_bytes(b"\0\xff\0"));
        // The complete set survives deletion of a receipt and its file.
        unlink(&r.root, "empty").unwrap();
        unlink(&r.journal, &format!("{}.json", hash_bytes(b"empty"))).unwrap();
        assert_eq!(index["files"][1]["name"], "empty");
        assert_eq!(index["files"][0]["name"], ".xodus-streaming.msixvc");
        assert_eq!(index["files"][0]["sha256"], hash_bytes(b"metadata"));
    }
    #[test]
    fn incomplete_or_duplicate_receipts_never_seal_an_index() {
        let d = root();
        let r = Resume::open(d.path()).unwrap();
        r.bind(&"a".repeat(64)).unwrap();
        r.prepare_cache().unwrap();
        assert!(r.finish_verified(&[("missing".into(), 0)]).is_err());
        let f = r.begin("present").unwrap();
        r.commit("present", 0, f).unwrap();
        assert!(
            r.finish_verified(&[("present".into(), 0), ("present".into(), 0)])
                .is_err()
        );
        assert!(r.finish_verified(&[("present".into(), 1)]).is_err());
        assert!(read_json(&r.journal, "integrity.json").is_err());
        assert!(!d.path().join(".xodus-streaming.msixvc").exists());
    }
    #[test]
    fn metadata_failure_never_seals_an_index() {
        let d = root();
        let r = Resume::open(d.path()).unwrap();
        r.bind(&"a".repeat(64)).unwrap();
        r.prepare_cache().unwrap();
        let f = r.begin("present").unwrap();
        r.commit("present", 0, f).unwrap();
        unlink(&r.root, ".xodus-streaming-tmp.msixvc").unwrap();
        assert!(r.finish_verified(&[("present".into(), 0)]).is_err());
        assert!(read_json(&r.journal, "integrity.json").is_err());
    }
}
