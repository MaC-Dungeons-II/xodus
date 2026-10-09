// SPDX-License-Identifier: GPL-3.0-only
//! Real, silent renewal shared by all broker connections. No synthetic tickets,
//! device provisioning, interactive windows, or credential deletion on failure.
use std::{future::Future, time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use crate::{api::live, models::{live::ExchangeUserTokenOutcome, secrets::{LegacyToken, Token}, soap}};
use super::{TokenManager, PASSPORT_STS, store::TokenStoreError};

const MARGIN: i64 = 120;
const DEADLINE: Duration = Duration::from_secs(20);
const RETRY: Duration = Duration::from_secs(15);
const HOST: &str = "000000004424da1f";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("sign_in_required")] SignInRequired,
    #[error("connection")] Connection,
    #[error("timeout")] Timeout,
    #[error("keyring")] Keyring,
    #[error("account_changed")] AccountChanged,
    #[error("error")] InvalidResponse,
}
impl SessionError {
    pub fn code(self) -> &'static str { match self {
        Self::SignInRequired => "sign_in_required", Self::Connection => "connection",
        Self::Timeout => "timeout", Self::Keyring => "keyring",
        Self::AccountChanged => "account_changed", Self::InvalidResponse => "error",
    }}
}
impl From<TokenStoreError> for SessionError {
    fn from(value: TokenStoreError) -> Self { match value {
        TokenStoreError::NotFound => Self::SignInRequired,
        _ => Self::Keyring,
    }}
}
impl From<live::RSTError> for SessionError {
    fn from(value: live::RSTError) -> Self { match value {
        live::RSTError::AuthenticationRejected => Self::SignInRequired,
        live::RSTError::Request(e) if e.is_timeout() => Self::Timeout,
        live::RSTError::Request(_) => Self::Connection,
        _ => Self::InvalidResponse,
    }}
}

#[derive(Default)]
pub(crate) struct RefreshState { failure: Option<([u8;32], Instant, SessionError)> }

fn legacy(token: Token) -> Result<LegacyToken, SessionError> {
    let Token::Legacy(token) = token else { return Err(SessionError::SignInRequired); };
    if token.token.is_empty() || token.token.len() > 1024*1024 { return Err(SessionError::SignInRequired); }
    let encrypted: soap::EncryptedData = quick_xml::de::from_str(&token.token).map_err(|_| SessionError::SignInRequired)?;
    if encrypted.cipher_data.cipher_value.is_empty() { return Err(SessionError::SignInRequired); }
    expiry(&token)?;
    Ok(token)
}
fn expiry(token: &LegacyToken) -> Result<i64, SessionError> {
    chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires).map(|t|t.timestamp()).map_err(|_|SessionError::SignInRequired)
}
fn fingerprint(tokens: &TokenManager) -> Result<([u8;32], String, LegacyToken), SessionError> {
    let user = tokens.get_user()?;
    if user.puid.is_empty() { return Err(SessionError::SignInRequired); }
    let token = legacy(tokens.get_user_sts_token()?)?;
    let bytes = serde_json::to_vec(&(&user.puid, &token)).map_err(|_|SessionError::Keyring)?;
    Ok((Sha256::digest(bytes).into(), user.puid, token))
}

/// Validates the requested root ticket by audience/key, never by response order.
pub fn renewed_sts(body: soap::BodyContent) -> Result<LegacyToken, SessionError> {
    let replies = match body {
        soap::BodyContent::RequestSecurityTokenResponse(t) => vec![*t],
        soap::BodyContent::RequestSecurityTokenResponseCollection(c) if c.challenges.is_empty() => c.security_tokens,
        _ => return Err(SessionError::InvalidResponse),
    };
    let mut result = None;
    for reply in replies {
        let address = reply.applies_to.endpoint_reference.address.as_str();
        let root = reply.requested_security_token.encrypted_data.as_ref()
            .is_some_and(|t| t.key_info.key_name.as_deref() == Some(PASSPORT_STS));
        if !root && address != "http://Passport.NET/tb" && address != PASSPORT_STS { continue; }
        if result.is_some() || !root || reply.token_type != "urn:passport:legacy"
            || !matches!(address, "http://Passport.NET/tb" | PASSPORT_STS) {
            return Err(SessionError::InvalidResponse);
        }
        let token = legacy(reply.into()).map_err(|_|SessionError::InvalidResponse)?;
        if expiry(&token)? <= chrono::Utc::now().timestamp() + MARGIN { return Err(SessionError::InvalidResponse); }
        result = Some(token);
    }
    result.ok_or(SessionError::InvalidResponse)
}

pub fn fault(pp: Option<&soap::PP>) -> SessionError {
    // Only an explicit Microsoft interactive challenge is a login requirement.
    // Unknown SOAP faults (including service outages) do not log the user out.
    if pp.and_then(soap::PP::interactive_auth_url).is_some() {
        SessionError::SignInRequired
    } else { SessionError::Connection }
}

pub(crate) async fn renew_device(client: &reqwest::Client, tokens: &TokenManager) -> Result<LegacyToken, SessionError> {
    match tokens.get_device_sts_token() {
        Ok(token) => {
            let token = legacy(token)?;
            if expiry(&token)? > chrono::Utc::now().timestamp() + MARGIN { return Ok(token); }
        }
        Err(TokenStoreError::NotFound) => (),
        Err(error) => return Err(error.into()),
    }
    // This is renewal of an existing device identity, never provisioning.
    let license = tokens.get_device_license()?;
    let sp = crate::licensing::splicense::SPLicense::parse_base64(&license.splicense).map_err(|_|SessionError::Keyring)?;
    let key = sp.clep_sign_state.ok_or(SessionError::Keyring)?.try_get_rsa_key().ok_or(SessionError::Keyring)?;
    let private = crate::licensing::utils::parse_bcrypt_rsa_private(&key).map_err(|_|SessionError::Keyring)?;
    let reply = live::authenticate_device(client, license.username.clone(), private).await?;
    let token = renewed_sts(reply.body.body)?;
    if tokens.get_device_license()?.device_id != license.device_id { return Err(SessionError::AccountChanged); }
    tokens.save_device_token(PASSPORT_STS.into(), Token::Legacy(token.clone()))?;
    Ok(token)
}

/// At most one bounded renewal per shared manager. Waiting callers re-read the
/// published credential; failures are briefly coalesced and reset by a new login.
pub async fn ensure_session(tokens: &TokenManager) -> Result<(), SessionError> {
    ensure_with(tokens, |old| async move {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none()).build().map_err(|_|SessionError::Connection)?;
        let device = renew_device(&client, tokens).await?;
        let user = tokens.get_user()?;
        match live::exchange_user_token(&client, old, user.username, device, None,
            Some("Silent".into()), HOST.into(), &[("http://Passport.NET/tb".into(), None)]).await? {
            ExchangeUserTokenOutcome::Issued(body) => renewed_sts(body),
            ExchangeUserTokenOutcome::Fault(pp) => Err(fault(pp.as_ref())),
        }
    }).await
}

async fn ensure_with<F, Fut>(tokens: &TokenManager, renew: F) -> Result<(), SessionError>
where F: FnOnce(LegacyToken) -> Fut, Fut: Future<Output=Result<LegacyToken, SessionError>> {
    tokio::time::timeout(DEADLINE, async {
        let mut state = tokens.session_refresh.lock().await;
        let (digest, puid, old) = fingerprint(tokens)?;
        if let Some((prior, until, err)) = state.failure {
            if digest == prior && Instant::now() < until { return Err(err); }
        }
        let now = chrono::Utc::now().timestamp();
        let current_device = tokens.get_device_sts_token().ok().and_then(|t|legacy(t).ok())
            .is_some_and(|t| expiry(&t).is_ok_and(|e|e > now + MARGIN));
        if expiry(&old)? > now + MARGIN && current_device { state.failure = None; return Ok(()); }
        // A separate timeout records a failure for coalesced callers as well.
        let result = match tokio::time::timeout(Duration::from_secs(18), renew(old.clone())).await {
            Ok(value) => value,
            Err(_) => Err(SessionError::Timeout),
        }.and_then(|new| {
            let new = legacy(Token::Legacy(new)).map_err(|_|SessionError::InvalidResponse)?;
            if expiry(&new)? <= chrono::Utc::now().timestamp() + MARGIN { return Err(SessionError::InvalidResponse); }
            Ok(new)
        });
        if fingerprint(tokens)?.0 != digest || tokens.get_user()?.puid != puid {
            return Err(SessionError::AccountChanged);
        }
        match result {
            Ok(new) => {
                if !tokens.replace_user_sts(&Token::Legacy(old), &Token::Legacy(new))? { return Err(SessionError::AccountChanged); }
                state.failure = None;
                Ok(())
            }
            Err(error) => { state.failure = Some((digest, Instant::now()+RETRY, error)); Err(error) }
        }
    }).await.map_err(|_|SessionError::Timeout)?
}

#[cfg(test)]
mod tests;
