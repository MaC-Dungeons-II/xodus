// SPDX-License-Identifier: GPL-3.0-only
//! Numeric-only, best-effort telemetry; this is never an installation receipt.
//! Payload totals exclude the metadata cache and HTTP transport overhead. Active
//! positions are logical received bytes, before verification, rounded only when
//! the completed output is durably committed. Resume credits full verified files.
use nix::libc;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_millis(500);
// POSIX guarantees atomic pipe writes up to at least 512 bytes. Six u64 fields
// and their fixed names fit comfortably; no names, paths or credentials occur.
const MAX_LINE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    received_bytes: u64,
    verified_bytes: u64,
    total_bytes: u64,
    completed_files: u64,
    total_files: u64,
}
impl Snapshot {
    fn line(self) -> Vec<u8> {
        format!(
            concat!(
                "{{\"format\":1,\"received_bytes\":{},\"verified_bytes\":{},",
                "\"total_bytes\":{},\"completed_files\":{},\"total_files\":{}}}\n"
            ),
            self.received_bytes,
            self.verified_bytes,
            self.total_bytes,
            self.completed_files,
            self.total_files
        )
        .into_bytes()
    }
}
#[derive(Default)]
struct Counters {
    snapshot: Option<Snapshot>,
    active: HashMap<usize, (u64, u64)>, // expected output length, received position
}
impl Counters {
    fn configure(&mut self, total: u64, files: u64, verified: u64, completed: u64) {
        if verified > total || completed > files {
            return;
        }
        self.active.clear();
        self.snapshot = Some(Snapshot {
            received_bytes: verified,
            verified_bytes: verified,
            total_bytes: total,
            completed_files: completed,
            total_files: files,
        });
    }
    fn start(&mut self, id: usize, length: u64) {
        if let Some(s) = self.snapshot {
            let assigned = self
                .active
                .values()
                .try_fold(s.verified_bytes, |sum, (size, _)| sum.checked_add(*size));
            if self.active.contains_key(&id)
                || self.active.len() as u64 >= s.total_files - s.completed_files
                || assigned
                    .and_then(|sum| sum.checked_add(length))
                    .is_none_or(|sum| sum > s.total_bytes)
            {
                return;
            }
            self.active.insert(id, (length, 0));
        }
    }
    fn advance(&mut self, id: usize, position: u64) {
        if let Some((length, previous)) = self.active.get_mut(&id) {
            *previous = (*previous).max(position.min(*length));
            self.update_received();
        }
    }
    fn finish(&mut self, id: usize) {
        if let Some((length, _)) = self.active.remove(&id) {
            if let Some(s) = self.snapshot.as_mut() {
                // start() already proved the bounded sum and file count.
                s.verified_bytes += length;
                s.completed_files += 1;
            }
            self.update_received();
        }
    }
    fn update_received(&mut self) {
        if let Some(s) = self.snapshot.as_mut() {
            s.received_bytes = self
                .active
                .values()
                .fold(s.verified_bytes, |sum, (_, pos)| sum + pos);
        }
    }
}
struct Pipe {
    file: File,
    last_attempt: Option<Instant>,
}
impl Pipe {
    fn inherited(fd: i32) -> io::Result<Self> {
        if fd < 3 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // Duplicating first validates the descriptor actually used below and
        // gives this module independent close ownership. Never open a pathname.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(duplicate) };
        if !file.metadata()?.file_type().is_fifo() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let flags = unsafe { libc::fcntl(duplicate, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != libc::O_WRONLY {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // pass_fds clears CLOEXEC on the inherited original. Closing our own
        // duplicate is insufficient: an unrelated future exec must inherit
        // neither descriptor, while the caller retains close ownership.
        let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if original_flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFD, original_flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(duplicate, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            last_attempt: None,
        })
    }
    fn emit(&mut self, snapshot: Snapshot, force: bool, now: Instant) -> io::Result<()> {
        if !force
            && self
                .last_attempt
                .is_some_and(|last| now.duration_since(last) < INTERVAL)
        {
            return Ok(());
        }
        self.last_attempt = Some(now);
        let bytes = snapshot.line();
        if bytes.len() > MAX_LINE {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        // One nonblocking <= PIPE_BUF write: a full pipe drops the whole sample,
        // never blocks a worker or leaves an unterminated partial JSON frame.
        match self.file.write(&bytes) {
            Ok(n) if n == bytes.len() => Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
            _ => Err(io::Error::from(io::ErrorKind::WriteZero)),
        }
    }
}
struct Inner {
    counters: Counters,
    pipe: Option<Pipe>,
}
impl Inner {
    fn emit(&mut self, force: bool) {
        if let (Some(pipe), Some(snapshot)) = (self.pipe.as_mut(), self.counters.snapshot) {
            if pipe.emit(snapshot, force, Instant::now()).is_err() {
                // A lost observer is unrelated to the licensed download itself.
                self.pipe = None;
            }
        }
    }
}
pub struct Progress(Option<Mutex<Inner>>);
impl Progress {
    pub fn new(fd: Option<i32>) -> io::Result<Self> {
        Ok(Self(
            fd.map(|fd| {
                Pipe::inherited(fd).map(|pipe| {
                    Mutex::new(Inner {
                        counters: Counters::default(),
                        pipe: Some(pipe),
                    })
                })
            })
            .transpose()?,
        ))
    }
    fn with(&self, action: impl FnOnce(&mut Inner)) {
        if let Some(inner) = &self.0 {
            if let Ok(mut inner) = inner.lock() {
                action(&mut inner);
            }
        }
    }
    pub fn configure(&self, total: u64, files: u64, verified: u64, completed: u64) {
        self.with(|inner| {
            inner.counters.configure(total, files, verified, completed);
            inner.emit(true);
        });
    }
    pub fn start(&self, id: usize, length: u64) {
        self.with(|inner| inner.counters.start(id, length));
    }
    pub fn advance(&self, id: usize, position: u64) {
        self.with(|inner| {
            inner.counters.advance(id, position);
            inner.emit(false);
        });
    }
    pub fn finish(&self, id: usize) {
        self.with(|inner| {
            inner.counters.finish(id);
            let finished = inner
                .counters
                .snapshot
                .is_some_and(|s| s.completed_files == s.total_files);
            inner.emit(finished);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    fn pipe() -> (File, File) {
        let mut descriptors = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        unsafe {
            (
                File::from_raw_fd(descriptors[0]),
                File::from_raw_fd(descriptors[1]),
            )
        }
    }
    fn read(reader: &mut File) -> String {
        let mut bytes = vec![];
        let mut b = [0; 4096];
        loop {
            match reader.read(&mut b) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&b[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        String::from_utf8(bytes).unwrap()
    }
    #[test]
    fn reused_parallel_active_padding_and_zero_length_are_separate_from_verified() {
        let mut c = Counters::default();
        c.configure(4096 + 12 + 5, 4, 5, 1);
        c.start(0, 4096);
        c.start(1, 12);
        c.start(2, 0);
        c.advance(0, 4095);
        c.advance(1, 10);
        assert_eq!(c.snapshot.unwrap().received_bytes, 4110);
        assert_eq!(c.snapshot.unwrap().verified_bytes, 5);
        c.advance(1, 2); // retry/late position never double counts or regresses
        assert_eq!(c.snapshot.unwrap().received_bytes, 4110);
        c.finish(0);
        c.finish(0); // one commit including encrypted padding
        assert_eq!(c.snapshot.unwrap().verified_bytes, 4101);
        c.finish(2);
        c.advance(1, u64::MAX);
        c.finish(1);
        let s = c.snapshot.unwrap();
        assert_eq!(
            (s.received_bytes, s.verified_bytes, s.completed_files),
            (4113, 4113, 4)
        );
        assert_eq!(s.total_bytes, 4113);
    }
    #[test]
    fn restart_initial_credit_is_only_the_new_verified_receipt_set() {
        let mut c = Counters::default();
        c.configure(100, 2, 20, 1);
        c.start(0, 80);
        c.advance(0, 77);
        assert_eq!(c.snapshot.unwrap().received_bytes, 97);
        c.configure(100, 2, 20, 1);
        assert_eq!(c.snapshot.unwrap().received_bytes, 20);
        c.start(0, 80);
        c.finish(0);
        assert_eq!(c.snapshot.unwrap().verified_bytes, 100);
    }
    #[test]
    fn numeric_schema_is_exact_and_bounded_even_at_u64_limits() {
        let s = Snapshot {
            received_bytes: u64::MAX,
            verified_bytes: u64::MAX,
            total_bytes: u64::MAX,
            completed_files: u64::MAX,
            total_files: u64::MAX,
        };
        let line = s.line();
        assert!(line.len() < MAX_LINE);
        assert_eq!(line.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 6);
        for name in [
            "format",
            "received_bytes",
            "verified_bytes",
            "total_bytes",
            "completed_files",
            "total_files",
        ] {
            assert!(object[name].is_u64());
        }
        assert_eq!(object["format"], 1);
    }
    #[test]
    fn initial_final_and_half_second_throttling_are_atomic() {
        let (mut reader, writer) = pipe();
        let mut p = Pipe::inherited(writer.as_raw_fd()).unwrap();
        let now = Instant::now();
        let s = Snapshot {
            received_bytes: 1,
            verified_bytes: 0,
            total_bytes: 2,
            completed_files: 0,
            total_files: 1,
        };
        p.emit(s, true, now).unwrap();
        p.emit(s, false, now + Duration::from_millis(499)).unwrap();
        p.emit(s, false, now + INTERVAL).unwrap();
        p.emit(s, true, now + INTERVAL).unwrap();
        assert_eq!(read(&mut reader).lines().count(), 3);
        let flags = unsafe { libc::fcntl(p.file.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    #[test]
    fn full_or_closed_pipe_never_blocks_or_affects_download_counters() {
        let (mut reader, mut writer) = pipe();
        let progress = Progress::new(Some(writer.as_raw_fd())).unwrap();
        let block = [b'x'; 4096];
        while writer.write(&block).is_ok() {}
        let before = Instant::now();
        progress.configure(50, 1, 0, 0);
        progress.start(1, 50);
        progress.advance(1, 20);
        assert!(before.elapsed() < Duration::from_secs(1));
        read(&mut reader);
        progress.finish(1);
        let result = read(&mut reader);
        let value: serde_json::Value = serde_json::from_str(result.trim()).unwrap();
        assert_eq!(value["verified_bytes"], 50);
        drop(reader);
        progress.configure(1, 1, 0, 0);
        progress.start(2, 1);
        progress.finish(2);
        assert!(progress.0.as_ref().unwrap().lock().unwrap().pipe.is_none());
    }
    #[test]
    fn invalid_descriptors_and_nonpipes_are_rejected_without_writing() {
        assert!(Progress::new(Some(0)).is_err());
        assert!(Progress::new(Some(-1)).is_err());
        let f = tempfile::tempfile().unwrap();
        assert!(Progress::new(Some(f.as_raw_fd())).is_err());
        assert_eq!(f.metadata().unwrap().len(), 0);
        let (reader, _writer) = pipe();
        assert!(Progress::new(Some(reader.as_raw_fd())).is_err());
        assert!(Progress::new(None).is_ok());
    }
    #[test]
    fn exec_inherits_neither_original_nor_duplicate_pipe() {
        let (_reader, writer) = pipe();
        // A high descriptor avoids mistaking a child's own standard-library
        // housekeeping descriptors for an inherited progress pipe.
        let fd = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(fd >= 64);
        let original = unsafe { File::from_raw_fd(fd) };
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let report = Pipe::inherited(fd).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(report.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", &format!("test ! -e /proc/self/fd/{fd}")])
            .status()
            .unwrap();
        assert!(status.success());
        assert!(original.metadata().is_ok()); // caller ownership is preserved
    }
    #[test]
    fn inconsistent_events_cannot_exceed_totals() {
        let mut c = Counters::default();
        c.configure(u64::MAX, 2, 0, 0);
        c.start(1, u64::MAX);
        c.start(2, 1);
        c.advance(1, u64::MAX);
        c.finish(1);
        let s = c.snapshot.unwrap();
        assert_eq!(s.verified_bytes, u64::MAX);
        assert_eq!(s.completed_files, 1);
        c.start(3, 0);
        c.finish(3);
        c.start(4, 0);
        c.finish(4);
        assert_eq!(c.snapshot.unwrap().completed_files, 2);
    }
}
