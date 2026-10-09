use super::*;
use crate::models::live::ExchangeUserTokenOutcome;

// Same response shape documented in Xodus docs/xbox/MSAUserLogin.md:
// Microsoft SOAP faults omit Action, To and Security. All values here are synthetic.
fn plain_fault(challenge: &str) -> String {
    format!(r#"<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope"
        xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">
      <S:Header><psf:pp><psf:inlineauthurl>{challenge}</psf:inlineauthurl></psf:pp></S:Header>
      <S:Body><S:Fault><S:Code><S:Value>S:Sender</S:Value><S:Subcode>
        <S:Value>wsse:FailedAuthentication</S:Value>
      </S:Subcode></S:Code></S:Fault></S:Body></S:Envelope>"#)
}

#[test]
fn minimal_fault_header_preserves_microsoft_verification_step() {
    for host in ["login.live.com", "account.live.com"] {
        let url = format!("https://{host}/synthetic-verification");
        for status in [reqwest::StatusCode::OK, reqwest::StatusCode::INTERNAL_SERVER_ERROR] {
            let signature = super::super::RSTSignature::Hmac {
                clep_secret: b"synthetic-device-secret", tpm_secret: &[],
            };
            let reply = parse_response(Some(signature), plain_fault(&url), status)
                .expect("a plain SOAP challenge must survive response decoding");
            let outcome = crate::api::live::user_exchange_outcome(reply.body.body, reply.header.pp).unwrap();
            let ExchangeUserTokenOutcome::Fault(Some(pp)) = outcome else { panic!("challenge lost") };
            assert_eq!(pp.interactive_auth_url(), Some(url.as_str()));
        }
    }
}

#[test]
fn minimal_fault_without_supported_challenge_does_not_become_success() {
    for url in ["", "http://login.live.com/no", "https://example.invalid/no",
        "https://user@login.live.com/no", "https://login.live.com:444/no"]
    {
        let reply = parse_response(None, plain_fault(url), reqwest::StatusCode::BAD_REQUEST).unwrap();
        assert!(matches!(crate::api::live::user_exchange_outcome(reply.body.body, reply.header.pp),
            Err(RSTError::AuthenticationRejected)));
    }
    let xml = plain_fault("");
    let start = xml.find("<S:Header>").unwrap();
    let end = xml.find("</S:Header>").unwrap() + "</S:Header>".len();
    let xml = format!("{}{}", &xml[..start], &xml[end..]);
    let reply = parse_response(None, xml, reqwest::StatusCode::BAD_REQUEST).unwrap();
    assert!(reply.header.pp.is_none());
    assert!(matches!(reply.body.body, soap::BodyContent::Fault(_)));
}

fn signature() -> super::super::RSTSignature<'static> {
    super::super::RSTSignature::Hmac { clep_secret: b"synthetic-device-secret", tpm_secret: &[] }
}

fn encrypt(plaintext: &[u8], arbitrary_padding: bool) -> soap::EncryptedData {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
    let nonce = b"synthetic-response-nonce";
    let key = signature().hmac_key(nonce).unwrap();
    let iv = [23_u8; 16];
    let padding = 16 - plaintext.len() % 16;
    let mut padded = plaintext.to_vec();
    padded.extend(std::iter::repeat_n(if arbitrary_padding { 0xa5 } else { padding as u8 }, padding - 1));
    padded.push(padding as u8);
    let mut ciphertext = vec![0; padded.len()];
    cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded_b2b::<NoPadding>(&padded, &mut ciphertext).unwrap();
    let mut bytes = iv.to_vec();
    bytes.extend(ciphertext);
    soap::EncryptedData {
        id: "SyntheticEncrypted".into(), xmlns: "http://www.w3.org/2001/04/xmlenc#".into(),
        el_type: "http://www.w3.org/2001/04/xmlenc#Element".into(),
        encryption_method: soap::EncryptionMethod {
            algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc".into(), val: None,
        },
        key_info: soap::KeyInfoWrap {
            ds: None, key_name: None,
            security_token_reference: Some(soap::SecurityTokenReference {
                reference: soap::ReferenceUri { uri: "#SignKey".into() },
            }),
        },
        cipher_data: soap::CipherData::new(BASE64_STANDARD.encode(bytes)),
    }
}

const FAULT: &str = "<Fault><faultcode>wsse:FailedAuthentication</faultcode></Fault>";
const PP: &str = "<pp><inlineauthurl>https://login.live.com/synthetic-verification</inlineauthurl></pp>";

fn signed_response(body: &str, pp: &str) -> String {
    let nonce = b"synthetic-response-nonce";
    let mut template = soap::Signature::empty_hmac();
    template.signed_info.reference = vec![soap::SignatureReference::exclusive("#ResponseBody"),
        soap::SignatureReference::exclusive("#ResponseHeader")];
    let template = quick_xml::se::to_string(&template).unwrap();
    let pp = pp.replacen('>', " wsu:Id=\"ResponseHeader\">", 1);
    let xml = format!(r##"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
      xmlns:wsa="http://www.w3.org/2005/08/addressing"
      xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
      xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
      xmlns:wssc="http://schemas.xmlsoap.org/ws/2005/02/sc">
      <s:Header><wsa:Action>synthetic-response</wsa:Action><wsa:To>synthetic-client</wsa:To>
      <wsse:Security><wsu:Timestamp><wsu:Created>2026-10-01T00:00:00Z</wsu:Created>
      <wsu:Expires>2026-10-01T00:05:00Z</wsu:Expires></wsu:Timestamp>
      <wssc:DerivedKeyToken wsu:Id="SignKey" Algorithm="urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED">
      <wssc:Nonce>{}</wssc:Nonce></wssc:DerivedKeyToken>{template}</wsse:Security>
      {pp}</s:Header>
      <s:Body wsu:Id="ResponseBody">{body}</s:Body></s:Envelope>"##, BASE64_STANDARD.encode(nonce));
    utils::sign_xml(Some(&signature()), nonce, xml).unwrap()
}

#[test]
fn signed_fault_is_checked_before_handoff() {
    let xml = signed_response(FAULT, PP);
    let reply = parse_response(Some(signature()), xml.clone(), reqwest::StatusCode::OK).unwrap();
    assert!(reply.header.pp.unwrap().interactive_auth_url().is_some());
    let tampered = xml.replace("wsse:FailedAuthentication", "s:Receiver");
    assert!(matches!(parse_response(Some(signature()), tampered, reqwest::StatusCode::OK),
        Err(RSTError::Response { step: ResponseStep::Signature, .. })));
    let tampered = xml.replace("/synthetic-verification", "/tampered");
    assert!(matches!(parse_response(Some(signature()), tampered, reqwest::StatusCode::OK),
        Err(RSTError::Response { step: ResponseStep::Signature, .. })));
}

#[test]
fn encrypted_challenge_and_body_support_xml_padding_and_large_responses() {
    for arbitrary in [false, true] {
        let pp = quick_xml::se::to_string(&soap::EncryptedPP { encrypted_data: encrypt(PP.as_bytes(), arbitrary) }).unwrap();
        let body = format!("<Fault><faultcode>wsse:FailedAuthentication</faultcode><faultstring>{}</faultstring></Fault>", "x".repeat(9000));
        let mut encrypted = encrypt(body.as_bytes(), arbitrary);
        encrypted.id = "SyntheticBody".into();
        let body = quick_xml::se::to_string(&encrypted).unwrap();
        let reply = parse_response(Some(signature()), signed_response(&body, &pp), reqwest::StatusCode::OK).unwrap();
        assert!(reply.header.pp.unwrap().interactive_auth_url().is_some());
        assert!(matches!(reply.body.body, soap::BodyContent::Fault(_)));
    }
}

// Hand-written wire response: exercise the entire decoder and root selection,
// rather than constructing the already-deserialized credential model.
const ISSUED_ROOT_COLLECTION: &str = r#"<wst:RequestSecurityTokenResponseCollection
      xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"
      xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"
      xmlns:wsa="http://www.w3.org/2005/08/addressing"
      xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wst:RequestSecurityTokenResponse>
        <wst:TokenType>urn:passport:legacy</wst:TokenType>
        <wsp:AppliesTo><wsa:EndpointReference><wsa:Address>http://Passport.NET/tb</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>
        <wst:Lifetime><wsu:Created>2026-01-01T00:00:00Z</wsu:Created><wsu:Expires>2999-01-01T00:00:00Z</wsu:Expires></wst:Lifetime>
        <wst:RequestedSecurityToken>
          <EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="SyntheticRoot" Type="http://www.w3.org/2001/04/xmlenc#Element">
            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyName>http://Passport.NET/STS</ds:KeyName></ds:KeyInfo>
            <CipherData><CipherValue>SYNTHETIC-ROOT</CipherValue></CipherData>
          </EncryptedData>
        </wst:RequestedSecurityToken>
      </wst:RequestSecurityTokenResponse>
    </wst:RequestSecurityTokenResponseCollection>"#;

#[test]
fn encrypted_successful_exchange_produces_a_usable_root_credential() {
    for arbitrary in [false, true] {
        let body = quick_xml::se::to_string(&encrypt(ISSUED_ROOT_COLLECTION.as_bytes(), arbitrary)).unwrap();
        let reply = parse_response(Some(signature()), signed_response(&body, PP), reqwest::StatusCode::OK).unwrap();
        let root = crate::tokens::session::renewed_sts(reply.body.body).unwrap();
        assert_eq!(root.key_name.as_deref(), Some("http://Passport.NET/STS"));
        assert!(root.token.contains("SYNTHETIC-ROOT"));
    }
}

#[test]
fn crypto_and_xml_failures_keep_the_exact_response_step() {
    for (plaintext, expected_pp, expected_body) in [
        (b"<not-closed>".as_slice(), ResponseStep::ChallengeXml, ResponseStep::BodyXml),
        (b"\xff".as_slice(), ResponseStep::ChallengeDecryption, ResponseStep::BodyDecryption),
    ] {
        let data = encrypt(plaintext, false);
        let body = quick_xml::se::to_string(&data).unwrap();
        let pp = quick_xml::se::to_string(&soap::EncryptedPP { encrypted_data: data }).unwrap();
        for (body, pp, expected) in [(FAULT, pp.as_str(), expected_pp), (body.as_str(), PP, expected_body)] {
            let error = parse_response(Some(signature()), signed_response(body, pp), reqwest::StatusCode::OK).unwrap_err();
            assert!(matches!(error, RSTError::Response { step, .. } if step == expected));
        }
    }
}

#[test]
fn malformed_ciphertext_returns_errors_without_panicking() {
    let nonces = HashMap::from([("SignKey".into(), BASE64_STANDARD.encode(b"synthetic-response-nonce"))]);
    for length in [0, 1, 15, 16, 17, 31, 33] {
        let mut encrypted = encrypt(PP.as_bytes(), false);
        encrypted.cipher_data.cipher_value = BASE64_STANDARD.encode(vec![0; length]);
        assert!(utils::decrypt_soap_encrypted_data::<soap::PP>(Box::new(encrypted), &signature(), &nonces).is_err());
    }
    for uri in ["", "#", "SignKey", "#unknown", "é"] {
        let mut encrypted = encrypt(PP.as_bytes(), false);
        encrypted.key_info.security_token_reference.as_mut().unwrap().reference.uri = uri.into();
        assert!(utils::decrypt_soap_encrypted_data::<soap::PP>(Box::new(encrypted), &signature(), &nonces).is_err());
    }
}

#[test]
fn malformed_responses_and_http_errors_are_distinct() {
    for (status, expected) in [(reqwest::StatusCode::OK, ResponseStep::Envelope),
        (reqwest::StatusCode::SERVICE_UNAVAILABLE, ResponseStep::HttpStatus)]
    {
        assert!(matches!(parse_response(None, "<html>unavailable</html>".into(), status),
            Err(RSTError::Response { step, .. }) if step == expected));
    }
    let data = quick_xml::se::to_string(&encrypt(FAULT.as_bytes(), false)).unwrap();
    let short = format!("<Envelope><Body>{data}</Body></Envelope>");
    assert!(matches!(parse_response(Some(signature()), short, reqwest::StatusCode::OK),
        Err(RSTError::Response { step: ResponseStep::Shape, .. })));
}

fn scoped_challenge(url: &str) -> String {
    format!(r#"<wst:RequestSecurityTokenResponse>
      <wsp:AppliesTo><wsa:EndpointReference><wsa:Address>scope=service::user.auth.xboxlive.com::MBI_SSL&amp;api-version=2.0</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>
      <psf:pp xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">
        <psf:reqstatus>synthetic-verification-required</psf:reqstatus>
        <psf:inlineauthurl>{url}</psf:inlineauthurl>
      </psf:pp>
    </wst:RequestSecurityTokenResponse>"#)
}

#[test]
fn scoped_verification_precedes_an_issued_root_in_a_mixed_response() {
    for host in ["login.live.com", "account.live.com"] {
        let url = format!("https://{host}/synthetic-scope-verification");
        for before_root in [true, false] {
            let challenge = scoped_challenge(&url);
            let mixed = if before_root {
                ISSUED_ROOT_COLLECTION.replacen("<wst:RequestSecurityTokenResponse>",
                    &format!("{challenge}<wst:RequestSecurityTokenResponse>"), 1)
            } else {
                ISSUED_ROOT_COLLECTION.replace("</wst:RequestSecurityTokenResponseCollection>",
                    &format!("{challenge}</wst:RequestSecurityTokenResponseCollection>"))
            };
            for encrypted in [true, false] {
                let body = if encrypted { quick_xml::se::to_string(&encrypt(mixed.as_bytes(), true)).unwrap() }
                    else { mixed.clone() };
                let reply = parse_response(Some(signature()), signed_response(&body, "<pp></pp>"), reqwest::StatusCode::OK).unwrap();
                assert!(crate::tokens::session::renewed_sts(reply.body.body.clone()).is_err(),
                    "must not persist the issued root while a scope still requires verification");
                let outcome = crate::api::live::user_exchange_outcome(reply.body.body, reply.header.pp).unwrap();
                let ExchangeUserTokenOutcome::Fault(Some(pp)) = outcome else { panic!("scoped challenge lost") };
                assert_eq!(pp.interactive_auth_url(), Some(url.as_str()));
                assert_eq!(crate::tokens::session::fault(Some(&pp)), crate::tokens::session::SessionError::SignInRequired);
            }
        }
    }
}

#[test]
fn scoped_rejection_cannot_silently_commit_an_issued_root() {
    for url in ["", "http://login.live.com/no", "https://example.invalid/no"] {
        let mixed = ISSUED_ROOT_COLLECTION.replacen("<wst:RequestSecurityTokenResponse>",
            &format!("{}<wst:RequestSecurityTokenResponse>", scoped_challenge(url)), 1);
        let body = quick_xml::se::to_string(&encrypt(mixed.as_bytes(), false)).unwrap();
        let reply = parse_response(Some(signature()), signed_response(&body, "<pp></pp>"), reqwest::StatusCode::OK).unwrap();
        assert!(crate::tokens::session::renewed_sts(reply.body.body.clone()).is_err());
        assert!(matches!(crate::api::live::user_exchange_outcome(reply.body.body, reply.header.pp),
            Err(RSTError::AuthenticationRejected)));
    }
    let incomplete = ISSUED_ROOT_COLLECTION.replace("<wst:TokenType>urn:passport:legacy</wst:TokenType>", "");
    let body = quick_xml::se::to_string(&encrypt(incomplete.as_bytes(), false)).unwrap();
    assert!(matches!(parse_response(Some(signature()), signed_response(&body, "<pp></pp>"), reqwest::StatusCode::OK),
        Err(RSTError::Response { step: ResponseStep::BodyXml, .. })));
}
