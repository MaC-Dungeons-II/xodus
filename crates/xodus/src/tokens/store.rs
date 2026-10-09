use std::time::Instant;

pub trait TokenBackend: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError>;
    fn remove(&self, key: &str) -> Result<(), TokenStoreError>;

    fn update(
        &self,
        key: &str,
        update: &dyn Fn(Option<Vec<u8>>) -> Result<Vec<u8>, TokenStoreError>,
    ) -> Result<(), TokenStoreError> {
        self.set(key, &update(self.get(key)?)?)
    }
}

pub trait ExpiringTokenBackend: TokenBackend {
    fn set_with_expiry(
        &self,
        key: &str,
        value: &[u8],
        expires_at: Instant,
    ) -> Result<(), TokenStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("keychain error: {0}")]
    Keychain(#[from] keyring_core::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("entry not found")]
    NotFound,
}
