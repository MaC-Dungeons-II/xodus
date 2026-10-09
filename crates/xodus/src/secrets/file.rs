use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use keyring_core::sample::credential::CredId;
use keyring_core::sample::{CredKey, Store};

use crate::tokens::store::TokenStoreError;

pub(super) fn initialize(path: &Path) -> Result<(), TokenStoreError> {
    let _lock = lock(path)?;
    super::prepare_private_backing_file(path)?;
    // Check format without retaining a writable process-local snapshot.
    let _ = Store::load_credentials(path_text(path)?)?;
    Ok(())
}

pub(super) fn with_entry<T>(
    path: &Path,
    user: &str,
    write: bool,
    operation: impl FnOnce(&keyring_core::Entry) -> Result<T, TokenStoreError>,
) -> Result<T, TokenStoreError> {
    let _lock = lock(path)?;
    super::prepare_private_backing_file(path)?;
    let store = Store::new_internal(Store::load_credentials(path_text(path)?)?, None);
    let entry = keyring_core::Entry::new_with_credential(Arc::new(CredKey {
        store: store.clone(),
        id: CredId {
            service: super::SERVICE_NAME.to_string(),
            user: user.to_string(),
        },
        uuid: None,
    }));
    let result = operation(&entry)?;
    if write {
        let content = ron::ser::to_string_pretty(&store.creds, ron::ser::PrettyConfig::new())
            .map_err(|_| std::io::Error::other("Unable to serialize keyring"))?;
        let parent = path.parent().expect("validated keyring parent");
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(content.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|err| err.error)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
    }
    Ok(result)
}

fn path_text(path: &Path) -> std::io::Result<&str> {
    path.to_str().ok_or_else(|| std::io::Error::other("Keyring path is not UTF-8"))
}

fn lock(path: &Path) -> std::io::Result<File> {
    super::validate_private_keyring_dir(path)?;
    // Lock a stable sidecar inode: the data file is replaced atomically.
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    let lock_path = std::path::PathBuf::from(name);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(&lock_path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            if !std::fs::symlink_metadata(&lock_path)?.is_file() {
                return Err(std::io::Error::other("Keyring lock must be a regular file"));
            }
            OpenOptions::new().read(true).write(true).open(&lock_path)?
        }
        Err(err) => return Err(err),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.lock()?;
    Ok(file)
}

#[cfg(test)]
mod tests;
