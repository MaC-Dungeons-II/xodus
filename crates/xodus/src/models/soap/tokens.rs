use serde::{Deserialize, Serialize};

use super::base::{AppliesTo, PP, PolicyReference, Timestamp};
use super::crypto::EncryptedData;
use crate::models::soap::{CipherData, EncryptionMethod};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityToken {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "wst:RequestType", alias = "RequestType")]
    pub request_type: String,
    #[serde(rename = "wsp:AppliesTo", alias = "AppliesTo")]
    pub applies_to: AppliesTo,
    #[serde(
        rename = "wsp:PolicyReference",
        alias = "PolicyReference",
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_reference: Option<PolicyReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityTokenResponse {
    #[serde(rename = "wst:TokenType", alias = "TokenType")]
    pub token_type: String,
    #[serde(rename = "wsp:AppliesTo", alias = "AppliesTo")]
    pub applies_to: AppliesTo,
    #[serde(rename = "wst:Lifetime", alias = "Lifetime")]
    pub lifetime: Timestamp,
    #[serde(
        rename = "wst:RequestedSecurityToken",
        alias = "RequestedSecurityToken"
    )]
    pub requested_security_token: RequestedSecurityToken,
    #[serde(rename = "wst:RequestedProofToken", alias = "RequestedProofToken")]
    pub requested_proof_token: Option<RequestedProofToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestedSecurityToken {
    #[serde(rename = "EncryptedData")]
    pub encrypted_data: Option<EncryptedData>,
    #[serde(rename = "wsse:BinarySecurityToken", alias = "BinarySecurityToken")]
    pub binary_security_token: Option<BinarySecurityTokenRes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BinarySecurityTokenRes {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "$value")]
    pub value: String,
    #[serde(rename = "@ValueType", skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BinarySecurityTokenReq {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@ValueType")]
    pub value_type: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedProofToken {
    #[serde(rename = "wst:BinarySecret", alias = "BinarySecret")]
    pub binary_secret: String,
    #[serde(rename = "EncryptedKey")]
    pub encrypted_key: Option<EncryptedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedKey {
    pub encryption_method: EncryptionMethod,
    pub cipher_data: CipherData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMultipleSecurityTokens {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@xmlns:ps")]
    pub ps: String,
    #[serde(rename = "wst:RequestSecurityToken")]
    pub security_tokens: Vec<RequestSecurityToken>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestSecurityTokenResponseCollection {
    #[serde(
        rename = "wst:RequestSecurityTokenResponse",
        alias = "RequestSecurityTokenResponse"
    )]
    pub security_tokens: Vec<RequestSecurityTokenResponse>,
    #[serde(rename = "wst:RequestSecurityTokenResponse", skip_serializing_if = "Vec::is_empty")]
    pub challenges: Vec<ScopedTokenChallenge>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedTokenChallenge {
    #[serde(rename = "wsp:AppliesTo")]
    pub applies_to: AppliesTo,
    #[serde(rename = "psf:pp")]
    pub pp: PP,
}

// A multi-scope reply can issue one token and return a verification step for
// another scope. Only this wire model accepts absent issued-token fields;
// callers still receive either a complete token or an explicit challenge.
#[derive(Deserialize)]
struct TokenResponseWire {
    #[serde(rename = "AppliesTo")]
    applies_to: AppliesTo,
    #[serde(rename = "TokenType")]
    token_type: Option<String>,
    #[serde(rename = "Lifetime")]
    lifetime: Option<Timestamp>,
    #[serde(rename = "RequestedSecurityToken")]
    requested_security_token: Option<RequestedSecurityToken>,
    #[serde(rename = "RequestedProofToken")]
    requested_proof_token: Option<RequestedProofToken>,
    #[serde(rename = "pp")]
    pp: Option<PP>,
}

impl<'de> Deserialize<'de> for RequestSecurityTokenResponseCollection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct CollectionWire {
            #[serde(rename = "RequestSecurityTokenResponse")]
            responses: Vec<TokenResponseWire>,
        }
        let wire = CollectionWire::deserialize(deserializer)?;
        let mut result = Self { security_tokens: Vec::new(), challenges: Vec::new() };
        for response in wire.responses {
            match (response.token_type, response.lifetime, response.requested_security_token) {
                (Some(token_type), Some(lifetime), Some(requested_security_token)) => {
                    result.security_tokens.push(RequestSecurityTokenResponse {
                        token_type, lifetime, requested_security_token,
                        applies_to: response.applies_to,
                        requested_proof_token: response.requested_proof_token,
                    });
                }
                (None, None, None) if response.requested_proof_token.is_none() => {
                    let pp = response.pp.ok_or_else(|| serde::de::Error::custom("missing token or verification step"))?;
                    result.challenges.push(ScopedTokenChallenge { applies_to: response.applies_to, pp });
                }
                _ => return Err(serde::de::Error::custom("incomplete token response")),
            }
        }
        Ok(result)
    }
}
