use std::collections::HashMap;

use base64::prelude::*;

use crate::api::live::utils;
use crate::models::soap;
use super::{RSTError, ResponseStep};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub struct RSTRequest<'a> {
    pub signed_xml: String,
    pub signature: Option<super::RSTSignature<'a>>,
}

impl<'a> RSTRequest<'a> {
    /// Makes a POST request with `reqwest::Client` and decrypts the envelope if applicable
    pub async fn request(
        self,
        client: &reqwest::Client,
    ) -> Result<soap::ResponseEnvelope, RSTError> {
        tracing::trace!("Making RST2.srf request");
        let mut response = client
        .post("https://login.live.com/RST2.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(self.signed_xml)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?;

        // SOAP faults can use HTTP 500. Parse them, but bound the body before
        // allocation and never treat an HTTP error with an issued token as success.
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(RSTError::InvalidResponse.at(ResponseStep::RateLimit));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(RSTError::InvalidResponse.at(ResponseStep::Size));
            }
            bytes.extend_from_slice(&chunk);
        }
        let response_text = String::from_utf8(bytes)
            .map_err(|_| RSTError::InvalidResponse.at(ResponseStep::Encoding))?;
        parse_response(self.signature, response_text, status)
    }
}

fn parse_response(
    signature: Option<super::RSTSignature<'_>>,
    response_text: String,
    status: reqwest::StatusCode,
) -> Result<soap::ResponseEnvelope, RSTError> {
    let envelope: soap::ResponseEnvelope = quick_xml::de::from_str(&response_text)
        .map_err(|error| RSTError::Deserialization(error).at(if status.is_success() {
            ResponseStep::Envelope
        } else { ResponseStep::HttpStatus }))?;
    let envelope = verify_and_decrypt_envelope(signature, response_text, envelope)?;
    if !status.is_success() && !matches!(envelope.body.body, soap::BodyContent::Fault(_)) {
        return Err(RSTError::InvalidResponse.at(ResponseStep::HttpStatus));
    }
    Ok(envelope)
}

fn verify_and_decrypt_envelope<'a>(
    signature: Option<super::RSTSignature<'a>>,
    xml_text: String,
    mut envelope: soap::ResponseEnvelope,
) -> Result<soap::ResponseEnvelope, RSTError> {
    // Only faults may omit the normal reply headers. A shortened header must
    // never make an incomplete token response acceptable as a successful login.
    if !matches!(envelope.body.body, soap::BodyContent::Fault(_))
        && (envelope.header.action.is_none() || envelope.header.to.is_none()
            || envelope.header.security.is_none())
    {
        return Err(RSTError::InvalidResponse.at(ResponseStep::Shape));
    }
    let Some(signature) = signature else {
        tracing::debug!("No signature, returning raw envelope");
        return Ok(envelope);
    };
    let Some(security) = envelope.header.security.as_ref() else {
        if envelope.header.encrypted_pp.is_some() {
            return Err(RSTError::MissingNonce.at(ResponseStep::ChallengeDecryption));
        }
        return Ok(envelope); // A plain fault, never an issued or encrypted token.
    };
    tracing::trace!("Decrypting soap::Envelope");
    let nonces: HashMap<String, String> = security
        .derived_key_tokens
        .iter()
        .map(|token| (token.id.clone(), token.nonce.clone()))
        .collect();

    if let Some(security_signature) = &security.signature {
        (|| -> Result<(), RSTError> {
        let key_info = security_signature.key_info.as_ref().ok_or(RSTError::MissingNonce)?;
        let id = &key_info.security_token_reference.reference.uri;
        let id = id.strip_prefix('#').filter(|id| !id.is_empty()).ok_or(super::RSTError::MissingNonce)?;
        let nonce = nonces.get(id).ok_or(super::RSTError::MissingNonce)?;
        let nonce = BASE64_STANDARD.decode(nonce)?;
        let key = signature.signing_key(&nonce)?;
        let mut kmgr = bergshamra::KeysManager::new();
        kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Verify));
        let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
        let result = bergshamra::verify(&ctx, &xml_text)?;
        match result {
            bergshamra::VerifyResult::Invalid { reason } => {
                return Err(super::RSTError::InvalidResponseSignature(reason));
            }
            bergshamra::VerifyResult::Valid { .. } => tracing::debug!("Verification successful"),
        }
        Ok(())
        })().map_err(|error| error.at(ResponseStep::Signature))?;
    }

    if envelope.header.pp.is_none()
        && let Some(enc_pp) = envelope.header.encrypted_pp.take()
    {
        tracing::trace!("Decrypting soap::PP");
        let pp = utils::decrypt_soap_encrypted_data(
            Box::new(enc_pp.encrypted_data),
            &signature,
            &nonces,
        ).map_err(|error| at_decryption(error, ResponseStep::ChallengeDecryption, ResponseStep::ChallengeXml))?;
        envelope.header.pp = pp;
    }

    if let soap::BodyContent::EncryptedData(enc_data) = envelope.body.body {
        tracing::trace!("Decrypting soap::Body");
        envelope.body.body = utils::decrypt_soap_encrypted_data(enc_data, &signature, &nonces)
            .map_err(|error| at_decryption(error, ResponseStep::BodyDecryption, ResponseStep::BodyXml))?;
    }

    Ok(envelope)
}

fn at_decryption(error: RSTError, decryption: ResponseStep, xml: ResponseStep) -> RSTError {
    let step = if matches!(error, RSTError::Deserialization(_)) { xml } else { decryption };
    error.at(step)
}

#[cfg(test)]
mod tests;
