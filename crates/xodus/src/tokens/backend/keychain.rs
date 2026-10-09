use crate::tokens::store::{TokenBackend, TokenStoreError};

pub struct KeychainBackend;

impl TokenBackend for KeychainBackend {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
        crate::secrets::with_entry(key, false, read_entry)
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError> {
        crate::secrets::with_entry(key, true, |entry| Ok(entry.set_secret(value)?))
    }

    fn remove(&self, key: &str) -> Result<(), TokenStoreError> {
        crate::secrets::with_entry(key, true, |entry| Ok(entry.delete_credential()?))
    }

    fn update(
        &self,
        key: &str,
        update: &dyn Fn(Option<Vec<u8>>) -> Result<Vec<u8>, TokenStoreError>,
    ) -> Result<(), TokenStoreError> {
        crate::secrets::with_entry(key, true, |entry| {
            Ok(entry.set_secret(&update(read_entry(entry)?)?)?)
        })
    }
}

fn read_entry(entry: &keyring_core::Entry) -> Result<Option<Vec<u8>>, TokenStoreError> {
    match entry.get_secret() {
        Ok(bytes) => Ok(Some(bytes)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(err) => Err(err.into()),
    }
}
