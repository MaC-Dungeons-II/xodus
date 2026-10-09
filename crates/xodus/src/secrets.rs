pub static SERVICE_NAME: &str = "Xodus Service";

#[cfg(feature = "key-chain-file")]
mod file;

pub fn init_secrets() -> Result<(), keyring_core::Error> {
    #[cfg(feature = "key-chain-file")]
    {
        // File operations reload and commit under a process-shared lock. Never
        // retain a sample Store with a backing path: its Drop would overwrite
        // changes made by another CLI or service process.
        file::initialize(&secrets_backing_file())
            .map_err(|err| keyring_core::Error::PlatformFailure(Box::new(err)))?;
    }

    #[cfg(not(feature = "key-chain-file"))]
    {
        #[cfg(target_os = "linux")]
        {
            keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
        }

        #[cfg(target_os = "macos")]
        {
            keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let store = keyring_core::sample::Store::new_with_configuration(
                &std::collections::HashMap::from([("persist", "true")]),
            )?;
            keyring_core::set_default_store(store);
        }
    }

    Ok(())
}

pub(crate) fn with_entry<T>(
    user: &str,
    write: bool,
    operation: impl FnOnce(&keyring_core::Entry) -> Result<T, crate::tokens::store::TokenStoreError>,
) -> Result<T, crate::tokens::store::TokenStoreError> {
    #[cfg(feature = "key-chain-file")]
    {
        file::with_entry(&secrets_backing_file(), user, write, operation)
    }
    #[cfg(not(feature = "key-chain-file"))]
    {
        let _ = write;
        operation(&keyring_core::Entry::new(SERVICE_NAME, user)?)
    }
}

pub fn destroy_secrets() {
    #[cfg(not(feature = "key-chain-file"))]
    keyring_core::unset_default_store();
}

#[cfg(feature = "key-chain-file")]
fn secrets_backing_file() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("XODUS_KEYRING_FILE") {
        return path.into();
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".xodus-keyring.ron")
}

#[cfg(feature = "key-chain-file")]
fn prepare_private_backing_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;

    validate_private_keyring_dir(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => file.write_all(b"{}")?,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_file() {
                return Err(std::io::Error::other("Keyring must be a regular file"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Err(err) => return Err(err),
    }
    Ok(())
}

#[cfg(feature = "key-chain-file")]
fn validate_private_keyring_dir(path: &std::path::Path) -> std::io::Result<()> {
    if !path.is_absolute() {
        return Err(std::io::Error::other("XODUS_KEYRING_FILE must be an absolute path"));
    }
    let parent = path.parent().ok_or_else(|| std::io::Error::other("Missing keyring directory"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() {
        return Err(std::io::Error::other("Keyring parent must be a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(std::io::Error::other("Keyring directory must have mode 0700"));
        }
    }

    Ok(())
}
