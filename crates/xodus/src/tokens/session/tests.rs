use super::*;
use crate::models::secrets::User;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

fn ticket(cipher: &str, expires: &str) -> LegacyToken {
    LegacyToken { key_name: Some(PASSPORT_STS.into()),
        token: quick_xml::se::to_string(&soap::EncryptedData::binary_da_token(cipher.into())).unwrap(),
        binary_secret: None, tpm_key: None,
        lifetime: soap::Timestamp { id: None, created: "2020-01-01T00:00:00Z".into(), expires: expires.into() },
    }
}
fn fresh() -> LegacyToken { ticket("SYNTHETIC-NEW", "2999-01-01T00:00:00Z") }
fn manager(expired: bool) -> TokenManager {
    let tokens = TokenManager::with_memory();
    tokens.save_user(&User { puid: "SYNTHETIC-USER".into(), username: "SYNTHETIC".into() }).unwrap();
    tokens.save_user_token(PASSPORT_STS.into(), Token::Legacy(if expired { ticket("SYNTHETIC-OLD", "2000-01-01T00:00:00Z") } else { fresh() })).unwrap();
    tokens.save_device_token(PASSPORT_STS.into(), Token::Legacy(fresh())).unwrap();
    tokens
}

#[tokio::test]
async fn valid_session_needs_no_network_and_missing_account_does_not_provision() {
    let unused = |_| async { panic!("must not exchange") };
    assert_eq!(ensure_with(&manager(false), unused).await, Ok(()));
    let missing = TokenManager::with_memory();
    assert_eq!(ensure_with(&missing, unused).await, Err(SessionError::SignInRequired));
    assert!(missing.get_device_license().is_err());
}

#[tokio::test]
async fn expired_session_is_replaced_once_for_concurrent_connections() {
    let tokens = manager(true);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut tasks = vec![];
    for _ in 0..12 {
        let (tokens, calls) = (tokens.clone(), calls.clone());
        tasks.push(tokio::spawn(async move { ensure_with(&tokens, |_| async {
            calls.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok(fresh())
        }).await }));
    }
    for task in tasks { assert_eq!(task.await.unwrap(), Ok(())); }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(expiry(&legacy(tokens.get_user_sts_token().unwrap()).unwrap()).unwrap(), expiry(&fresh()).unwrap());
}

#[tokio::test]
async fn transient_and_interactive_failures_are_distinct_and_do_not_destroy_credentials() {
    for error in [SessionError::Connection, SessionError::Timeout, SessionError::SignInRequired, SessionError::InvalidResponse] {
        let tokens = manager(true);
        let before = fingerprint(&tokens).unwrap().0;
        assert_eq!(ensure_with(&tokens, |_| async { Err(error) }).await, Err(error));
        assert_eq!(fingerprint(&tokens).unwrap().0, before);
        // A retry burst must not produce repeated requests or login windows.
        assert_eq!(ensure_with(&tokens, |_| async { panic!("backoff") }).await, Err(error));
        tokens.save_user_token(PASSPORT_STS.into(), Token::Legacy(fresh())).unwrap();
        assert_eq!(ensure_with(&tokens, |_| async { panic!("new login is current") }).await, Ok(()));
    }
}

#[tokio::test]
async fn refresh_cannot_overwrite_a_new_login_or_logout() {
    for switch in [false, true] {
        let tokens = manager(true);
        let result = ensure_with(&tokens, |_| async {
            if switch {
                tokens.save_user(&User { puid:"OTHER".into(), username:"SYNTHETIC".into() }).unwrap();
                tokens.save_user_token(PASSPORT_STS.into(), Token::Legacy(ticket("OTHER", "2999-01-01T00:00:00Z"))).unwrap();
            } else { tokens.remove_persistent().unwrap(); }
            Ok(fresh())
        }).await;
        assert!(matches!(result, Err(SessionError::AccountChanged | SessionError::SignInRequired)));
        assert_eq!(tokens.get_user().ok().map(|u|u.puid), if switch {Some("OTHER".into())} else {None});
    }
}

#[tokio::test]
async fn expired_or_malformed_renewal_is_never_persisted() {
    for new in [ticket("SYNTHETIC", "2000-01-01T00:00:00Z"), ticket("", "2999-01-01T00:00:00Z")] {
        let tokens = manager(true); let old = fingerprint(&tokens).unwrap().0;
        assert_eq!(ensure_with(&tokens, |_| async { Ok(new) }).await, Err(SessionError::InvalidResponse));
        assert_eq!(fingerprint(&tokens).unwrap().0, old);
        assert_eq!(ensure_with(&tokens, |_| async { panic!("invalid replies must back off") }).await, Err(SessionError::InvalidResponse));
    }
}

fn reply(address: &str, cipher: &str) -> soap::RequestSecurityTokenResponse {
    let mut data = soap::EncryptedData::binary_da_token(cipher.into());
    data.key_info.key_name = Some(PASSPORT_STS.into());
    soap::RequestSecurityTokenResponse {
        token_type:"urn:passport:legacy".into(),
        applies_to:soap::AppliesTo { endpoint_reference:soap::EndpointReference { address:address.into() } },
        lifetime:fresh().lifetime,
        requested_security_token:soap::RequestedSecurityToken { encrypted_data:Some(data), binary_security_token:None },
        requested_proof_token:None,
    }
}
#[test]
fn root_response_requires_correct_audience_key_validity_and_cardinality() {
    let valid = reply("http://Passport.NET/tb", "SYNTHETIC");
    assert!(renewed_sts(soap::BodyContent::RequestSecurityTokenResponse(Box::new(valid.clone()))).is_ok());
    for wrong in [reply("https://other.invalid", "SYNTHETIC"), reply(PASSPORT_STS, "")] {
        assert!(renewed_sts(soap::BodyContent::RequestSecurityTokenResponse(Box::new(wrong))).is_err());
    }
    assert!(renewed_sts(soap::BodyContent::RequestSecurityTokenResponseCollection(soap::RequestSecurityTokenResponseCollection {security_tokens:vec![valid.clone(), valid],challenges:vec![]})).is_err());
}

#[test]
fn only_explicit_microsoft_challenges_request_interactive_login() {
    assert_eq!(fault(None), SessionError::Connection);
    for (url, expected) in [("https://login.live.com/ppsecure/reauth",SessionError::SignInRequired),
        ("https://account.live.com/proofs/",SessionError::SignInRequired),
        ("https://login.live.com.evil.invalid/",SessionError::Connection),
        ("http://login.live.com/",SessionError::Connection), ("https://user@login.live.com/",SessionError::Connection)] {
        let pp:soap::PP = quick_xml::de::from_str(&format!("<pp><inlineauthurl>{url}</inlineauthurl></pp>")).unwrap();
        assert_eq!(fault(Some(&pp)),expected);
    }
}
