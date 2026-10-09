use crate::hardware;
use crate::licensing::utils::generate_string;
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use super::{session::{SessionError, renew_device}, store::TokenStoreError};
use crate::tokens::manager::TokenManager;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(client: &reqwest::Client, tokens: &TokenManager) -> Result<(), SessionError> {
    match tokens.get_device_license() {
        Err(TokenStoreError::NotFound) => provision_device(client, tokens).await,
        Err(error) => Err(error.into()),
        Ok(_) if !device_token_is_current(tokens.get_device_sts_token().ok().as_ref()) => {
            renew_device(client, tokens).await.map(|_|())
        }
        Ok(_) => Ok(()),
    }
}

async fn provision_device(client: &reqwest::Client, tokens: &TokenManager) -> Result<(), SessionError> {
    let username = format!("02{}", generate_string(14));
    let password = generate_string(20);
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: hardware::probe_provision_components(),
            tpm_info: None,
        }),
    };

    let dev = crate::api::live::login_device_credential(client, provision)
        .await?;

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens
        .save_device_license(&device)?;

    renew_device(client, tokens).await.map(|_|())
}

// A persisted credential is not evidence that its STS ticket is still valid.
// Reuse the device's existing identity/reauthentication path after expiry.
fn device_token_is_current(token: Option<&crate::models::secrets::Token>) -> bool {
    let Some(crate::models::secrets::Token::Legacy(token)) = token else {
        return false;
    };
    chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)
        .is_ok_and(|expiry| expiry.timestamp() > chrono::Utc::now().timestamp() + 60)
}
#[cfg(test)]
mod resume_expiry_tests {
    use super::*;
    #[test]
    fn device_sts_presence_does_not_hide_expiry() {
        use crate::models::{
            secrets::{LegacyToken, Token},
            soap::Timestamp,
        };
        let token = |expires: &str| {
            Token::Legacy(LegacyToken {
                key_name: None,
                token: String::new(),
                binary_secret: None,
                tpm_key: None,
                lifetime: Timestamp {
                    id: None,
                    created: String::new(),
                    expires: expires.into(),
                },
            })
        };
        assert!(!device_token_is_current(None));
        assert!(!device_token_is_current(Some(&Token::Compact(
            "synthetic".into()
        ))));
        assert!(!device_token_is_current(Some(&token(
            "2000-01-01T00:00:00Z"
        ))));
        assert!(!device_token_is_current(Some(&token("bad"))));
        assert!(device_token_is_current(Some(&token(
            "2999-01-01T00:00:00Z"
        ))));
    }
}
