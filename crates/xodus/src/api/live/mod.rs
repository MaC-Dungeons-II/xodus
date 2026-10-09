use base64::prelude::*;
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;

mod rst;
mod utils;
pub use rst::{RSTError, ResponseStep};

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> Result<DeviceAddResponse, rst::RSTError> {
    let data = quick_xml::se::to_string(&data)?;

    let response = client
        .post("https://login.live.com/ppsecure/deviceaddcredential.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?;
    let text = response.error_for_status()?.text().await?;
    let resp: DeviceAddResponse = quick_xml::de::from_str(&text)?;
    Ok(resp)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: rsa::RsaPrivateKey,
) -> Result<soap::ResponseEnvelope, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(Box::new(private_key)))
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    request.request(client).await
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(token.binary_secret.as_ref().ok_or(rst::RSTError::InvalidCredential)?)?;
    let secret: [u8; 4096] = secret.try_into().map_err(|_| rst::RSTError::InvalidCredential)?;
    if u32::from_le_bytes(secret[..4].try_into().map_err(|_|rst::RSTError::InvalidCredential)?) != 4 { return Err(rst::RSTError::InvalidCredential); }
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let request = rst::RSTRequestBuilder::new()
        .sso_flags("SsoRestr")
        .hosting_app(&hosting_app)
        .device_token(token)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        })
        .scope_policy(&scope, policy)
        .build()?;

    let envelope = request.request(client).await?;

    match envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(*res),
        soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection) => {
            if !collection.challenges.is_empty() || collection.security_tokens.len() != 1 { return Err(rst::RSTError::InvalidResponse); }
            Ok(collection.security_tokens.remove(0))
        }
        _ => Err(rst::RSTError::InvalidResponse),
    }
}

// Each parameter maps directly to a distinct SOAP request field; grouping them
// into a params struct would just move the sprawl rather than reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_user_token(
    client: &reqwest::Client,
    user_token: LegacyToken,
    username: String,
    device_token: LegacyToken,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> Result<ExchangeUserTokenOutcome, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(device_token.binary_secret.as_ref().ok_or(rst::RSTError::InvalidCredential)?)?;
    let secret: [u8; 4096] = secret.try_into().map_err(|_| rst::RSTError::InvalidCredential)?;
    if u32::from_le_bytes(secret[..4].try_into().map_err(|_|rst::RSTError::InvalidCredential)?) != 4 { return Err(rst::RSTError::InvalidCredential); }
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let mut builder = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::user_hint(username))
        .device_token(device_token)
        .user_token(Token::Legacy(user_token))
        .hosting_app(&hosting_app)
        .sso_flags("SsoRestr")
        .license_signature_key_version(None)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        });

    if let Some(ux) = inline_ux.as_deref() {
        builder = builder.inline_ux(ux);
    }
    if let Some(ft) = inline_token.as_deref() {
        builder = builder.inline_ft(ft);
    }
    for (scope, policy) in scope_policies {
        builder = builder.scope_policy(scope, policy.clone());
    }

    let request = builder.build()?;
    let envelope = request.request(client).await?;

    user_exchange_outcome(envelope.body.body, envelope.header.pp)
}

fn user_exchange_outcome(body: soap::BodyContent, pp: Option<soap::PP>) -> Result<ExchangeUserTokenOutcome, rst::RSTError> {
    Ok(match body {
        // Microsoft can put PP inside a scope's RSTR, alongside an issued root
        // token for another scope. Complete the required verification before
        // accepting or storing any token from that collection.
        soap::BodyContent::RequestSecurityTokenResponseCollection(collection)
            if !collection.challenges.is_empty() => {
                let pp = collection.challenges.into_iter().map(|challenge| challenge.pp)
                    .find(|pp| pp.interactive_auth_url().is_some())
                    .ok_or(rst::RSTError::AuthenticationRejected)?;
                ExchangeUserTokenOutcome::Fault(Some(pp))
            }
        // A credential fault may carry the next interactive sign-in step.
        // Preserve it for the login handler; silent renewal still reports that
        // sign-in is required. Only a rejection without that step is terminal.
        soap::BodyContent::Fault(fault) if fault.rejects_credentials()
            && pp.as_ref().and_then(soap::PP::interactive_auth_url).is_none() =>
                return Err(rst::RSTError::AuthenticationRejected),
        soap::BodyContent::Fault(_) => ExchangeUserTokenOutcome::Fault(pp),
        body => ExchangeUserTokenOutcome::Issued(body),
    })
}

#[cfg(test)]
mod auth_fault_tests {
    use super::*;
    #[test]
    fn credential_fault_with_inline_challenge_remains_interactive() {
        for xml in [
            "<Fault><faultcode>wsse:FailedAuthentication</faultcode></Fault>",
            "<Fault><Code><Value>s:Sender</Value><Subcode><Value>wsse:InvalidSecurityToken</Value></Subcode></Code></Fault>",
        ] {
            for challenge in ["https://login.live.com/continue", "https://account.live.com/continue"] {
                let fault = quick_xml::de::from_str::<soap::Fault>(xml).unwrap();
                let pp = quick_xml::de::from_str::<soap::PP>(&format!(
                    "<PP><inlineauthurl>{challenge}</inlineauthurl></PP>"
                )).unwrap();
                let outcome = user_exchange_outcome(soap::BodyContent::Fault(fault), Some(pp));
                let Ok(ExchangeUserTokenOutcome::Fault(Some(pp))) = outcome else {
                    panic!("An interactive challenge was discarded as a terminal login failure");
                };
                assert_eq!(pp.inline_auth_url.as_deref(), Some(challenge));
                assert_eq!(pp.interactive_auth_url(), Some(challenge));
                assert_eq!(crate::tokens::session::fault(Some(&pp)),
                    crate::tokens::session::SessionError::SignInRequired);
            }
        }
    }
    #[test]
    fn credential_fault_without_valid_challenge_stays_rejected() {
        for challenge in [
            "", "relative/path", "http://login.live.com/continue",
            "https://example.invalid/continue", "https://login.live.com.example.invalid/continue",
            "https://login.live.com:444/continue", "https://user@login.live.com/continue",
            "https://user:password@login.live.com/continue", "javascript:void(0)",
        ] {
            let fault = quick_xml::de::from_str::<soap::Fault>(
                "<Fault><faultcode>wsse:FailedAuthentication</faultcode></Fault>"
            ).unwrap();
            let pp = quick_xml::de::from_str::<soap::PP>(&format!(
                "<PP><inlineauthurl>{challenge}</inlineauthurl></PP>"
            )).unwrap();
            assert_eq!(pp.interactive_auth_url(), None);
            assert!(matches!(user_exchange_outcome(soap::BodyContent::Fault(fault), Some(pp)),
                Err(rst::RSTError::AuthenticationRejected)));
        }
    }
    #[test]
    fn credential_rejection_without_inline_url_requires_login_but_service_faults_do_not() {
        for (xml, requires_login) in [
            ("<Fault><faultcode>wsse:FailedAuthentication</faultcode></Fault>",true),
            ("<Fault><Code><Value>s:Sender</Value><Subcode><Value>wsse:InvalidSecurityToken</Value></Subcode></Code></Fault>",true),
            ("<Fault><faultcode>s:Server</faultcode><faultstring>Temporary failure</faultstring></Fault>",false),
            ("<Fault><Code><Value>s:Receiver</Value></Code></Fault>",false),
            ("<Fault/>",false),
        ] {
            let fault=quick_xml::de::from_str::<soap::Fault>(xml).unwrap();
            let result=user_exchange_outcome(soap::BodyContent::Fault(fault),None);
            if requires_login {
                assert_eq!(crate::tokens::session::SessionError::from(result.unwrap_err()),crate::tokens::session::SessionError::SignInRequired);
            } else { assert!(matches!(result,Ok(ExchangeUserTokenOutcome::Fault(None)))); }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::api::live::exchange_device_token;
    use crate::models::secrets::Token;
    use crate::models::soap;
    use crate::tokens::TokenManager;
    use crate::tokens::device::ensure_device_credentials;

    #[tokio::test]
    async fn test_get_xbox_live_dev_token() {
        let client = reqwest::Client::new();

        let mgr = TokenManager::with_memory();
        ensure_device_credentials(&client, &mgr).await.unwrap();

        let token: Token = mgr.get_device_sts_token().unwrap();
        let Token::Legacy(token) = token else {
            todo!("no a LegacyToken");
        };
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .unwrap();

        let ms_device_token: Token = resp.into();
        let Token::Compact(ms_device_token) = ms_device_token else {
            todo!("Unsupported token");
        };

        println!("{}", ms_device_token);
    }
}
