use super::*;
use crate::models::secrets::{Token, TokenStore};
use crate::tokens::TokenManager;

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn read(path: &Path, key: &str) -> Vec<u8> {
    with_entry(path, key, false, |entry| Ok(entry.get_secret()?)).unwrap()
}

#[test]
fn legacy_format_round_trip_and_failed_update() {
    let directory = private_directory();
    let path = directory.path().join("synthetic.ron");
    initialize(&path).unwrap();
    {
        let store = Store::new_with_backing(path.to_str().unwrap()).unwrap();
        let entry = keyring_core::Entry::new_with_credential(Arc::new(CredKey {
            store,
            id: CredId {
                service: crate::secrets::SERVICE_NAME.to_string(),
                user: "synthetic".to_string(),
            },
            uuid: None,
        }));
        entry.set_secret(b"before").unwrap();
    }
    assert_eq!(read(&path, "synthetic"), b"before");
    let failed: Result<(), TokenStoreError> = with_entry(&path, "synthetic", true, |entry| {
        entry.set_secret(b"must-not-commit")?;
        Err(TokenStoreError::NotFound)
    });
    assert!(failed.is_err());
    assert_eq!(read(&path, "synthetic"), b"before");
    with_entry(&path, "synthetic", true, |entry| Ok(entry.set_secret(b"after")?)).unwrap();
    let loaded = Store::load_credentials(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(read(&path, "synthetic"), b"after");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn parallel_processes_preserve_all_scope_updates() {
    let directory = private_directory();
    let path = directory.path().join("synthetic.ron");
    initialize(&path).unwrap();
    let executable = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for writer in 0..4 {
        children.push(std::process::Command::new(&executable)
            .args(["--ignored", "--exact", "secrets::file::tests::child_writer", "--test-threads=1"])
            .env("XODUS_KEYRING_FILE", &path)
            .env("XODUS_SYNTHETIC_TEST_WRITER", writer.to_string())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap());
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let tokens: TokenStore = serde_json::from_slice(&read(&path, "user-tokens")).unwrap();
    assert_eq!(tokens.tokens.len(), 100);
    for writer in 0..4 {
        for iteration in 0..25 {
            let key = format!("synthetic-{writer}-{iteration}");
            assert!(matches!(tokens.tokens.get(&key), Some(Token::Compact(value)) if value == &key));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777, 0o700);
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            assert_eq!(entry.unwrap().metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}

#[test]
#[ignore = "spawned by parallel_processes_preserve_all_scope_updates"]
fn child_writer() {
    let Ok(writer) = std::env::var("XODUS_SYNTHETIC_TEST_WRITER") else { return };
    crate::secrets::init_secrets().unwrap();
    let manager = TokenManager::with_keychain_and_memory();
    for iteration in 0..25 {
        let key = format!("synthetic-{writer}-{iteration}");
        manager.save_user_token(key.clone(), Token::Compact(key)).unwrap();
        std::thread::yield_now();
    }
    // Exit without dropping stores: every successful save must already persist.
    std::process::exit(0);
}

#[cfg(unix)]
#[test]
fn rejects_permissive_directory_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = private_directory();
    let path = directory.path().join("synthetic.ron");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(initialize(&path).is_err());
    assert!(!path.exists());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = directory.path().join("unrelated");
    std::fs::write(&target, b"untouched").unwrap();
    symlink(&target, &path).unwrap();
    assert!(initialize(&path).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    std::fs::remove_file(&path).unwrap();
    let lock_path = directory.path().join("synthetic.ron.lock");
    std::fs::remove_file(&lock_path).unwrap();
    symlink(&target, &lock_path).unwrap();
    assert!(initialize(&path).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
}
