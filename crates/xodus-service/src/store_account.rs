//! Read-only selection of the broker's real configured MSA account. No XUser,
//! authentication exchange, credential write, or license assertion is involved.
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xodus::models::{secrets::Token, soap};
use xodus::tokens::TokenManager;

#[derive(PartialEq, Eq)]
struct Snapshot { digest: [u8; 32], expires_at: i64, identity: Option<[u8;32]> }

#[derive(Default)]
pub struct BrokerStoreAccount {
    // Deliberately no Debug; only a digest and opaque random ID survive a read.
    selected: Option<(Snapshot, String)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreAccountContextRequest {}

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
enum Status { Available, Unavailable, Expired, Error, Timeout }

#[derive(Serialize)]
#[serde(rename = "StoreAccountContextResponse", rename_all = "PascalCase")]
struct Response {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

fn valid_request(input: &[u8]) -> Result<(), ()> {
    // Existing native XML packets may include one trailing terminator.
    let input = input.strip_suffix(&[0]).unwrap_or(input);
    if input.len() > 128 || input.contains(&0) { return Err(()); }
    let mut reader = Reader::from_reader(input);
    let mut roots = 0;
    let mut depth = 0;
    loop {
        match reader.read_event().map_err(|_| ())? {
            Event::Start(element) => {
                if depth != 0 || element.name().as_ref() != "StoreAccountContextRequest"
                    || element.attributes().next().is_some() { return Err(()); }
                roots += 1; depth += 1;
            }
            Event::Empty(element) => {
                if depth != 0 || element.name().as_ref() != "StoreAccountContextRequest"
                    || element.attributes().next().is_some() { return Err(()); }
                roots += 1;
            }
            Event::End(_) => { if depth != 1 { return Err(()); } depth -= 1; }
            Event::Text(text) if text.as_ref().chars().all(|c| c.is_ascii_whitespace()) => (),
            Event::Decl(_) if roots == 0 => (),
            Event::Eof => break,
            _ => return Err(()),
        }
    }
    if roots != 1 || depth != 0 { return Err(()); }
    let _: StoreAccountContextRequest = quick_xml::de::from_reader(input).map_err(|_| ())?;
    Ok(())
}

fn snapshot(tokens: &TokenManager) -> Result<Snapshot, Status> {
    let Token::Legacy(token) = tokens.get_user_sts_token().map_err(|_| Status::Unavailable)?
        else { return Err(Status::Unavailable); };
    if token.token.is_empty() || token.token.len() > 1024 * 1024 { return Err(Status::Unavailable); }
    // Parse the same encrypted credential the real MSA exchange consumes. This
    // validates local structure only; current server acceptance is not implied.
    let encrypted: soap::EncryptedData = quick_xml::de::from_str(&token.token)
        .map_err(|_| Status::Unavailable)?;
    if encrypted.cipher_data.cipher_value.is_empty() { return Err(Status::Unavailable); }
    let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)
        .map_err(|_| Status::Unavailable)?.timestamp();
    let bytes = serde_json::to_vec(&token).map_err(|_| Status::Unavailable)?;
    let identity=tokens.get_user().ok().filter(|u| !u.puid.is_empty()).map(|u|Sha256::digest(u.puid.as_bytes()).into());
    Ok(Snapshot { digest: Sha256::digest(bytes).into(), expires_at: expiry, identity })
}

impl BrokerStoreAccount {
    pub async fn session_response(&mut self, request: &[u8], tokens: &TokenManager) -> Result<Vec<u8>, ()> {
        valid_request(request)?;
        if snapshot(tokens).is_err() { self.selected = None; }
        if let Err(error) = xodus::tokens::session::ensure_session(tokens).await {
            use xodus::tokens::session::SessionError;
            let status = match error {
                SessionError::SignInRequired => Status::Expired,
                SessionError::AccountChanged => { self.selected = None; Status::Unavailable },
                SessionError::Timeout => Status::Timeout,
                _ => Status::Error,
            };
            return quick_xml::se::to_string(&Response { status, context: None }).map(String::into_bytes).map_err(|_|());
        }
        self.response(request, tokens)
    }

    pub async fn prepare(&mut self, context: &str, tokens: &TokenManager) -> Result<(), crate::store_license::Status> {
        use crate::store_license::Status as S;
        let current = match snapshot(tokens) {
            Ok(current) => current,
            Err(_) => { self.selected = None; return Err(S::Unavailable); },
        };
        if !self.same_account(&current) { self.selected = None; return Err(S::Unavailable); }
        if !self.selected.as_ref().is_some_and(|(old, id)| id == context
            && (old == &current || old.identity.is_some() && old.identity == current.identity)) {
            return Err(S::Unavailable);
        }
        xodus::tokens::session::ensure_session(tokens).await.map_err(|e| match e {
            xodus::tokens::session::SessionError::SignInRequired => S::Expired,
            xodus::tokens::session::SessionError::AccountChanged => S::Unavailable,
            xodus::tokens::session::SessionError::Timeout => S::Timeout,
            _ => S::Error,
        })?;
        if self.validate_context(context, tokens) { Ok(()) } else { Err(S::Unavailable) }
    }

    pub fn response(&mut self, request: &[u8], tokens: &TokenManager) -> Result<Vec<u8>, ()> {
        valid_request(request)?;
        self.response_at(tokens, chrono::Utc::now().timestamp())
    }

    fn response_at(&mut self, tokens: &TokenManager, now: i64) -> Result<Vec<u8>, ()> {
        let response = match snapshot(tokens) {
            Ok(snapshot) if snapshot.expires_at <= now => {
                // An expired ticket grants no access, but expiry alone is not
                // an account switch. The game retains its Store context while
                // the same account refreshes its ticket. Keep that opaque ID
                // only when real account metadata still identifies its owner.
                if !self.same_account(&snapshot) { self.selected = None; }
                Response { status: Status::Expired, context: None }
            }
            Ok(snapshot) => {
                if !self.selected.as_ref().is_some_and(|(old, _)| old == &snapshot || old.identity.is_some() && old.identity==snapshot.identity) {
                    let random: [u8; 32] = rand::random();
                    // A zero context is reserved as invalid by the native parser.
                    if random == [0; 32] { return Err(()); }
                    let context = random.iter().map(|byte| format!("{byte:02x}")).collect();
                    self.selected = Some((snapshot, context));
                } else if let Some((old,_))=&mut self.selected {
                    *old=snapshot;
                }
                Response { status: Status::Available, context: self.selected.as_ref().map(|(_, value)| value.clone()) }
            }
            Err(status) => { self.selected = None; Response { status, context: None } }
        };
        quick_xml::se::to_string(&response).map(String::into_bytes).map_err(|_| ())
    }

    fn same_account(&self, current: &Snapshot) -> bool {
        current.identity.is_some() && self.selected.as_ref()
            .is_some_and(|(old, _)| old.identity == current.identity)
    }

    /// A normal STS refresh does not switch accounts. License operations require
    /// real broker metadata; it remains private and is never returned by IPC.
    pub fn validate_context(&mut self,context:&str,tokens:&TokenManager)->bool {
        let Ok(current)=snapshot(tokens) else{self.selected=None;return false;};
        let now=chrono::Utc::now().timestamp();
        if !self.same_account(&current) {self.selected=None;return false;}
        // Preserve identity across a refresh gap, never validity. Every Store
        // operation still requires a current, unexpired ticket before/after I/O.
        if current.expires_at<=now {return false;}
        let valid=self.selected.as_ref().is_some_and(|(_,id)|id==context);
        if valid {if let Some((old,_))=&mut self.selected {*old=current;}}
        valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xodus::models::secrets::LegacyToken;
    use xodus::tokens::PASSPORT_STS;
    fn seed(tokens: &TokenManager, cipher: &str, expiry: &str) {
        let token = LegacyToken {
            key_name: Some(PASSPORT_STS.into()),
            token: quick_xml::se::to_string(&soap::EncryptedData::binary_da_token(cipher.into())).unwrap(),
            binary_secret: None, tpm_key: None,
            lifetime: soap::Timestamp { id: None, created: "2020-01-01T00:00:00Z".into(), expires: expiry.into() },
        };
        tokens.save_user_token(PASSPORT_STS.into(), Token::Legacy(token)).unwrap();
    }
    #[test]
    fn empty_and_terminated_requests_only() {
        for valid in [b"<StoreAccountContextRequest/>".as_slice(), b"<StoreAccountContextRequest/>\0", b"<StoreAccountContextRequest></StoreAccountContextRequest>"] { assert!(valid_request(valid).is_ok()); }
        for invalid in [b"<Other/>".as_slice(), b"<StoreAccountContextRequest user='x'/>", b"<StoreAccountContextRequest><XUser/></StoreAccountContextRequest>", b"<StoreAccountContextRequest/>\0\0", b"<!DOCTYPE x><StoreAccountContextRequest/>", b"<StoreAccountContextRequest/><StoreAccountContextRequest/>"] { assert!(valid_request(invalid).is_err()); }
    }
    #[test]
    fn account_is_real_snapshot_without_xuser_or_metadata() {
        let tokens = TokenManager::with_memory();
        seed(&tokens, "SYNTHETIC-CIPHER-A", "2040-01-01T00:00:00Z");
        let mut state = BrokerStoreAccount::default();
        let first = state.response_at(&tokens, 1).unwrap();
        assert!(String::from_utf8_lossy(&first).contains("<Status>Available</Status>"));
        assert_eq!(first, state.response_at(&tokens, 1).unwrap());
        assert!(!String::from_utf8_lossy(&first).contains("SYNTHETIC"));
        seed(&tokens, "SYNTHETIC-CIPHER-B", "2040-01-01T00:00:00Z");
        assert_ne!(first, state.response_at(&tokens, 1).unwrap());
    }
    #[test]
    fn missing_expired_malformed_and_wrong_token_type_fail_closed() {
        let tokens = TokenManager::with_memory();
        let mut state = BrokerStoreAccount::default();
        assert_eq!(state.response_at(&tokens, 1).unwrap(), b"<StoreAccountContextResponse><Status>Unavailable</Status></StoreAccountContextResponse>");
        seed(&tokens, "SYNTHETIC", "2000-01-01T00:00:00Z");
        assert_eq!(state.response_at(&tokens, 2_000_000_000).unwrap(), b"<StoreAccountContextResponse><Status>Expired</Status></StoreAccountContextResponse>");
        seed(&tokens, "SYNTHETIC", "invalid");
        assert!(String::from_utf8_lossy(&state.response_at(&tokens, 1).unwrap()).contains("Unavailable"));
        tokens.save_user_token(PASSPORT_STS.into(), Token::Compact("SYNTHETIC".into())).unwrap();
        assert!(String::from_utf8_lossy(&state.response_at(&tokens, 1).unwrap()).contains("Unavailable"));
    }
    #[test]
    fn same_broker_refresh_preserves_context_but_account_switch_does_not() {
        let tokens=TokenManager::with_memory();let mut state=BrokerStoreAccount::default();
        tokens.save_user(&xodus::models::secrets::User{puid:"SYNTHETIC_ACCOUNT_A".into(),username:"SYNTHETIC_NAME".into()}).unwrap();
        seed(&tokens,"SYNTHETIC_A","2040-01-01T00:00:00Z");let first=state.response_at(&tokens,1).unwrap();let context=state.selected.as_ref().unwrap().1.clone();
        seed(&tokens,"SYNTHETIC_REFRESH","2041-01-01T00:00:00Z");assert!(state.validate_context(&context,&tokens));assert_eq!(first,state.response_at(&tokens,1).unwrap());
        tokens.save_user(&xodus::models::secrets::User{puid:"SYNTHETIC_ACCOUNT_B".into(),username:"SYNTHETIC_NAME".into()}).unwrap();assert!(!state.validate_context(&context,&tokens));assert_ne!(first,state.response_at(&tokens,1).unwrap());
    }
    #[test]
    fn expired_refresh_gap_recovers_the_existing_game_context() {
        for query_account_during_expiry in [false, true] {
            let tokens = TokenManager::with_memory();
            tokens.save_user(&xodus::models::secrets::User {puid:"SYNTHETIC_A".into(), username:"SYNTHETIC".into()}).unwrap();
            let mut state = BrokerStoreAccount::default();
            seed(&tokens, "FIRST", "2040-01-01T00:00:00Z");
            let first = state.response_at(&tokens, 2_000_000_000).unwrap();
            let context = state.selected.as_ref().unwrap().1.clone();
            seed(&tokens, "EXPIRED", "2000-01-01T00:00:00Z");
            if query_account_during_expiry {
                let response = state.response_at(&tokens, 2_000_000_000).unwrap();
                assert!(String::from_utf8_lossy(&response).contains("<Status>Expired</Status>"));
                assert!(!String::from_utf8_lossy(&response).contains("<Context>"));
            }
            assert!(!state.validate_context(&context, &tokens));
            seed(&tokens, "REFRESHED", "2041-01-01T00:00:00Z");
            assert!(state.validate_context(&context, &tokens), "the game retains its Store context during a normal refresh");
            assert_eq!(first, state.response_at(&tokens, 2_000_000_000).unwrap());
            assert!(!state.validate_context("wrong-context", &tokens));
        }
    }

    #[test]
    fn expired_different_account_or_logout_invalidates_the_old_context() {
        for logout in [false, true] {
            let tokens = TokenManager::with_memory();
            let user = xodus::models::secrets::User {puid:"SYNTHETIC_A".into(), username:"SYNTHETIC".into()};
            tokens.save_user(&user).unwrap();
            seed(&tokens, "FIRST", "2040-01-01T00:00:00Z");
            let mut state = BrokerStoreAccount::default();
            let first = state.response_at(&tokens, 2_000_000_000).unwrap();
            let context = state.selected.as_ref().unwrap().1.clone();
            if logout {
                tokens.remove_persistent().unwrap();
            } else {
                tokens.save_user(&xodus::models::secrets::User {puid:"SYNTHETIC_B".into(),username:"SYNTHETIC".into()}).unwrap();
                seed(&tokens, "EXPIRED_B", "2000-01-01T00:00:00Z");
            }
            assert!(!state.validate_context(&context, &tokens));
            tokens.save_user(&user).unwrap();
            seed(&tokens, "REFRESHED_A", "2041-01-01T00:00:00Z");
            assert!(!state.validate_context(&context, &tokens));
            assert_ne!(first, state.response_at(&tokens, 2_000_000_000).unwrap());
        }
    }
    #[test]
    fn account_query_also_invalidates_a_different_expired_identity() {
        let tokens = TokenManager::with_memory();
        tokens.save_user(&xodus::models::secrets::User {puid:"SYNTHETIC_A".into(), username:"SYNTHETIC".into()}).unwrap();
        seed(&tokens, "FIRST", "2040-01-01T00:00:00Z");
        let mut state = BrokerStoreAccount::default();
        state.response_at(&tokens, 2_000_000_000).unwrap();
        tokens.save_user(&xodus::models::secrets::User {puid:"SYNTHETIC_B".into(),username:"SYNTHETIC".into()}).unwrap();
        seed(&tokens, "EXPIRED_B", "2000-01-01T00:00:00Z");
        state.response_at(&tokens, 2_000_000_000).unwrap();
        assert!(state.selected.is_none());
    }

}
