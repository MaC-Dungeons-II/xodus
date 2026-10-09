use std::cmp::min;
use std::collections::HashMap;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use rsa::rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zerocopy::IntoBytes;

use crate::api::live::rst;
use crate::models::soap;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// SP800_108 HMAC with counter
/// - key_usage - KDF_LABEL
/// - context - KDF_CONTEXT
pub fn generate_shared_key(
    key_length: usize,
    in_key: &[u8],
    key_usage: &str,
    context: &[u8],
) -> [u8; 32] {
    let len: usize = 4 + key_usage.len() + 1 + context.len() + 4;
    let mut shared_key_material: Vec<u8> = vec![0; len];

    let mut offset = 0;
    offset += 4;
    shared_key_material[offset..offset + key_usage.len()].copy_from_slice(key_usage.as_bytes());
    offset += key_usage.len();

    // Already zerod
    offset += 1;

    shared_key_material[offset..offset + context.len()].copy_from_slice(context);
    offset += context.len();

    let key_bit_length = u32::try_from(key_length * 8).unwrap();
    shared_key_material[offset..offset + 4].copy_from_slice(&key_bit_length.to_be_bytes());

    offset += 4;

    let mut current_key_length: usize = 0;
    let mut current_hash_count: u32 = 1;

    let mut shared_key = [0; 32];

    while current_key_length < key_length {
        shared_key_material[0..4].copy_from_slice(&current_hash_count.to_be_bytes());

        current_hash_count += 1;

        type HmacSha256 = Hmac<Sha256>;

        let mut hmac = HmacSha256::new_from_slice(in_key).unwrap();
        hmac.update(&shared_key_material[..offset]);
        let signature = hmac.finalize().into_bytes();
        let amount = min(signature.len(), key_length - current_key_length);
        shared_key[current_key_length..current_key_length + amount]
            .copy_from_slice(&signature.as_bytes()[0..amount]);
        current_key_length += amount;
    }

    shared_key
}

pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    _ = OsRng.try_fill_bytes(&mut nonce);
    nonce
}

pub fn sign_xml(
    signature: Option<&super::rst::RSTSignature>,
    nonce: &[u8],
    xml_text: String,
) -> Result<String, rst::RSTBuilderError> {
    let Some(signature) = signature else {
        return Ok(xml_text);
    };
    let min_xml = bergshamra::c14n::canonicalize(
        &xml_text,
        bergshamra_c14n::C14nMode::Exclusive,
        None,
        &[] as &[&str],
    )?;

    let mut kmgr = bergshamra::KeysManager::new();
    let key = signature.signing_key(nonce)?;

    kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Sign));
    let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
    let signed = bergshamra::sign(&ctx, std::str::from_utf8(&min_xml).unwrap())?;
    Ok(signed)
}

pub fn decrypt_soap_encrypted_data<T: serde::de::DeserializeOwned>(
    encrypted_data: Box<soap::EncryptedData>,
    signature: &rst::RSTSignature,
    nonces: &HashMap<String, String>,
) -> Result<T, rst::RSTError> {
    let id = &encrypted_data.key_info.security_token_reference
        .as_ref().ok_or(rst::RSTError::MissingNonce)?
        .reference
        .uri;

    let id = id.strip_prefix('#').filter(|id| !id.is_empty()).ok_or(rst::RSTError::MissingNonce)?;
    let nonce = nonces.get(id).ok_or(rst::RSTError::MissingNonce)?;
    let nonce = BASE64_STANDARD.decode(nonce)?;
    let key = signature.hmac_key(&nonce).ok_or(rst::RSTError::HmacKey)?;
    let cipher_value = BASE64_STANDARD.decode(encrypted_data.cipher_data.cipher_value)?;

    if encrypted_data.encryption_method.algorithm != "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        || cipher_value.len() < 32 || cipher_value.len() > 2 * 1024 * 1024
        || cipher_value.len() % 16 != 0
    {
        return Err(rst::RSTError::InvalidResponse);
    }
    let (iv, encrypted) = cipher_value.split_at(16);
    let iv: &[u8; 16] = iv.try_into().map_err(|_| rst::RSTError::InvalidResponse)?;
    let decryptor = Aes256CbcDec::new(&key.into(), iv.into());
    let mut block = vec![0; encrypted.len()];
    let plaintext = decryptor.decrypt_padded_b2b::<NoPadding>(encrypted, &mut block)
        .map_err(|_| rst::RSTError::InvalidResponse)?;
    // XML Encryption CBC padding permits arbitrary bytes followed by the pad
    // length (W3C XML Encryption 1.1, section 5.2.1), not only PKCS#7 bytes.
    let padding = usize::from(*plaintext.last().ok_or(rst::RSTError::InvalidResponse)?);
    if !(1..=16).contains(&padding) || padding > plaintext.len() {
        return Err(rst::RSTError::InvalidResponse);
    }
    let result = std::str::from_utf8(&plaintext[..plaintext.len() - padding])
        .map_err(|_| rst::RSTError::InvalidResponse)?;
    let data = quick_xml::de::from_str::<T>(result)?;

    Ok(data)
}
