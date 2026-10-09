// Temporary context, full service design will be much more extensive

use std::sync::Arc;

use xodus::tokens::TokenManager;

pub struct SimpleContext {
    pub client: reqwest::Client,
    tokens: Arc<TokenManager>,
    pub store_account: crate::store_account::BrokerStoreAccount,
    pub store_license: crate::store_license::LicenseCache,
    pub store_collections: crate::store_collections::Broker,
    pub store_inventory: crate::store_inventory::Broker,
    pub store_purchase: crate::store_purchase::Broker,
}

impl SimpleContext {
    pub fn new(tokens: Arc<TokenManager>) -> Self {
        let client = reqwest::ClientBuilder::new()
            .user_agent(format!("xodus-service/{}", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        Self {
            client,
            tokens,
            store_account: Default::default(),
            store_license: Default::default(),
            store_collections: Default::default(),
            store_inventory: Default::default(),
            store_purchase: Default::default(),
        }
    }

    pub fn tokens(&self) -> &Arc<TokenManager> {
        &self.tokens
    }
}
