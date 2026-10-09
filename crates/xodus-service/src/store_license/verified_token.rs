//! Microsoft-documented PC license token validation. Inputs/claims have no Debug
//! implementation and are never logged. Public certificate fetch has a fixed origin.
use base64::prelude::*;
use openssl::{hash::MessageDigest,pkey::Id,sign::Verifier,x509::X509};
use serde_json::Value;

pub struct VerifiedToken {
    pub products: Vec<Product>,
    pub expires_at: i64,
    pub not_before: i64,
}
#[derive(Clone)]
pub struct Product { pub product_id: String, pub sku_id: String, pub ends_at: i64 }

pub fn nonce() -> Result<String,&'static str> {
    use std::io::Read;
    let mut bytes=[0;32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).map_err(|_|"nonce")?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

pub async fn verify(client:&reqwest::Client, token:&str, nonce:&str) -> Result<VerifiedToken,&'static str> {
    if token.len()>1024*1024 {return Err("token_size");}
    let parts:Vec<_>=token.split('.').collect();
    if parts.len()!=3 {return Err("token_format");}
    let header:Value=serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_|"header_encoding")?).map_err(|_|"header_json")?;
    if header["alg"].as_str()!=Some("RS256") {return Err("signature_algorithm");}
    let claims:Value=serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_|"claims_encoding")?).map_err(|_|"claims_json")?;
    let encoded=claims["LicenseTokenClaim"].as_str().ok_or("license_claim_missing")?;
    let inner=BASE64_STANDARD.decode(encoded).map_err(|_|"license_claim_encoding")?;
    let start=inner.iter().position(|&b|b==b'{').ok_or("license_claim_prefix")?;
    if start>256 {return Err("license_claim_prefix");}
    let license:Value=serde_json::from_slice(&inner[start..]).map_err(|_|"license_claim_json")?;
    let certificate_id=license["certificateId"].as_str().ok_or("certificate_id")?;
    if certificate_id.is_empty() || certificate_id.len()>128 || !certificate_id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-') {return Err("certificate_id");}
    let url=format!("https://licensing.mp.microsoft.com/v8.0/licenseToken/fullCertificate/{certificate_id}");
    let mut response=client.get(url).send().await.map_err(|_|"certificate_request")?.error_for_status().map_err(|_|"certificate_status")?;
    let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await.map_err(|_|"certificate_body")? {
        if bytes.len()+chunk.len()>256*1024 {return Err("certificate_size");}
        bytes.extend_from_slice(&chunk);
    }
    let cert=decode_certificate(&bytes)?;
    verify_with_certificate(token,nonce,&cert,chrono::Utc::now().timestamp())
}

fn verify_with_certificate(token:&str,nonce:&str,cert:&X509,now:i64)->Result<VerifiedToken,&'static str> {
    if token.len()>1024*1024 {return Err("token_size");}
    let parts:Vec<_>=token.split('.').collect();
    if parts.len()!=3 {return Err("token_format");}
    let header:Value=serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_|"header_encoding")?).map_err(|_|"header_json")?;
    if header["alg"].as_str()!=Some("RS256") {return Err("signature_algorithm");}
    let claims:Value=serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_|"claims_encoding")?).map_err(|_|"claims_json")?;
    let encoded=claims["LicenseTokenClaim"].as_str().ok_or("license_claim_missing")?;
    let inner=BASE64_STANDARD.decode(encoded).map_err(|_|"license_claim_encoding")?;
    let start=inner.iter().position(|&b|b==b'{').ok_or("license_claim_prefix")?;
    if start>256 {return Err("license_claim_prefix");}
    let license:Value=serde_json::from_slice(&inner[start..]).map_err(|_|"license_claim_json")?;
    let der=cert.to_der().map_err(|_|"certificate_der")?;
    let thumbprint=BASE64_URL_SAFE_NO_PAD.encode(openssl::sha::sha1(&der));
    if header["x5t"].as_str().map(|s|s.trim_end_matches('='))!=Some(thumbprint.as_str()) {return Err("certificate_thumbprint");}
    let time=openssl::asn1::Asn1Time::from_unix(now).map_err(|_|"clock")?;
    if cert.not_before()>time || cert.not_after()<time {return Err("certificate_expired");}
    let key=cert.public_key().map_err(|_|"certificate_public_key")?;
    if key.id()!=Id::RSA || key.bits()<2048 {return Err("certificate_key_type");}
    let signature=BASE64_URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_|"signature_encoding")?;
    let mut verifier=Verifier::new(MessageDigest::sha256(),&key).map_err(|_|"signature_setup")?;
    verifier.update(format!("{}.{}",parts[0],parts[1]).as_bytes()).map_err(|_|"signature_setup")?;
    if !verifier.verify(&signature).map_err(|_|"signature_verify")? {return Err("signature_invalid");}
    let expires_at=claims["exp"].as_i64().ok_or("jwt_expiry")?;
    let not_before=claims["nbf"].as_i64().ok_or("jwt_not_before")?;
    if expires_at<=now || not_before>now || expires_at<=not_before {return Err("jwt_expired");}
    if license["tokenVersion"].as_u64()!=Some(1) {return Err("token_version");}
    // Microsoft documents no literal issuer/audience contract here. Trust comes
    // from the fixed-origin TLS exchange, the Microsoft certificate/signature,
    // current signed token dates, and the unique request nonce. Do not invent a
    // stricter literal gate or use arbitrary audience values as account IDs.
    if license["customDeveloperString"].as_str()!=Some(nonce) {return Err("nonce_mismatch");}
    let items=license["licensableProducts"].as_array().ok_or("products_missing")?;
    if items.len()>128 {return Err("product_count");}
    let mut products=Vec::new();
    for item in items {
        let product_id=item["productId"].as_str().ok_or("product_id")?;
        let sku_id=item["skuId"].as_str().ok_or("sku_id")?;
        if product_id.len()!=12 || !product_id.bytes().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit()) || sku_id.len()!=4 || !sku_id.bytes().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit()) {return Err("product_id_format");}
        let end=item["endDate"].as_str().ok_or("product_expiry")?;
        let ends_at=chrono::DateTime::parse_from_rfc3339(end).map_err(|_|"product_expiry")?.timestamp();
        if let Some(existing)=products.iter().find(|p:&&Product|p.product_id==product_id&&p.sku_id==sku_id) {
            if existing.ends_at!=ends_at {return Err("conflicting_duplicate_product");}
        } else {products.push(Product{product_id:product_id.into(),sku_id:sku_id.into(),ends_at});}
    }
    Ok(VerifiedToken{products,expires_at,not_before})
}

fn decode_certificate(bytes:&[u8]) -> Result<X509,&'static str> {
    if let Ok(cert)=X509::from_der(bytes) {return Ok(cert);}
    if let Ok(cert)=X509::from_pem(bytes) {return Ok(cert);}
    let json:Value=serde_json::from_slice(bytes).map_err(|_|"certificate_json")?;
    let text=json.as_str().or_else(||json["certificate"].as_str()).or_else(||json["Certificate"].as_str()).ok_or("certificate_field")?;
    let der=BASE64_STANDARD.decode(text).map_err(|_|"certificate_base64")?;
    X509::from_der(&der).map_err(|_|"certificate_parse")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{asn1::Asn1Time,pkey::{PKey,Private},rsa::Rsa,sign::Signer,x509::X509NameBuilder};
    use serde_json::json;
    fn cert()->(PKey<Private>,X509) {
        let key=PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();let mut name=X509NameBuilder::new().unwrap();name.append_entry_by_text("CN","Synthetic License Test").unwrap();let name=name.build();
        let mut cert=X509::builder().unwrap();cert.set_version(2).unwrap();cert.set_subject_name(&name).unwrap();cert.set_issuer_name(&name).unwrap();cert.set_pubkey(&key).unwrap();cert.set_not_before(&Asn1Time::from_unix(1_000).unwrap()).unwrap();cert.set_not_after(&Asn1Time::from_unix(10_000).unwrap()).unwrap();cert.sign(&key,MessageDigest::sha256()).unwrap();(key,cert.build())
    }
    fn token(key:&PKey<Private>,cert:&X509,license:Value,mutate:impl FnOnce(&mut Value))->String {
        let header=json!({"alg":"RS256","x5t":BASE64_URL_SAFE_NO_PAD.encode(openssl::sha::sha1(&cert.to_der().unwrap()))});
        let mut claims=json!({"iss":"https://licensing.mp.microsoft.com","aud":"https://licensing.mp.microsoft.com","nbf":2000,"exp":4000,"LicenseTokenClaim":BASE64_STANDARD.encode(format!("prefix{license}"))});mutate(&mut claims);
        let body=format!("{}.{}",BASE64_URL_SAFE_NO_PAD.encode(header.to_string()),BASE64_URL_SAFE_NO_PAD.encode(claims.to_string()));let mut signer=Signer::new(MessageDigest::sha256(),key).unwrap();signer.update(body.as_bytes()).unwrap();format!("{body}.{}",BASE64_URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap()))
    }
    fn license()->Value {json!({"certificateId":"synthetic-id","customDeveloperString":"SYNTHETIC_NONCE","tokenVersion":1,"licensableProducts":[{"productId":"ABCD1234EFGH","skuId":"0001","endDate":"2040-01-01T00:00:00Z"}]})}
    #[test]
    fn caller_challenge_is_exact_signed_content_and_empty_products_are_valid() {
        let (key,cert)=cert();
        for challenge in ["  &<>\"'\r\n\t Österreich 🛫  ", "FIRST_CALLER_NONCE", "SECOND_CALLER_NONCE"] {
            let mut l=license();l["customDeveloperString"]=json!(challenge);l["licensableProducts"]=json!([]);
            let signed=token(&key,&cert,l,|_|{});let original=signed.clone();
            assert!(verify_with_certificate(&signed,challenge,&cert,3000).unwrap().products.is_empty());
            assert_eq!(signed,original);
            assert_eq!(verify_with_certificate(&signed,&format!("{challenge}changed"),&cert,3000).err(),Some("nonce_mismatch"));
        }
    }
    #[test]
    fn signed_token_nonce_time_version_and_duplicates() {
        let (key,cert)=cert();let good=token(&key,&cert,license(),|_|{});
        let verified=verify_with_certificate(&good,"SYNTHETIC_NONCE",&cert,3000).unwrap();assert_eq!(verified.products.len(),1);assert_eq!(verified.expires_at,4000);
        assert_eq!(verify_with_certificate(&good,"WRONG_NONCE",&cert,3000).err(),Some("nonce_mismatch"));
        assert_eq!(verify_with_certificate(&good,"SYNTHETIC_NONCE",&cert,4000).err(),Some("jwt_expired"));
        assert_eq!(verify_with_certificate(&good,"SYNTHETIC_NONCE",&cert,1999).err(),Some("jwt_expired"));
        let alternate=token(&key,&cert,license(),|c|c["iss"]=json!("other signed issuer"));assert!(verify_with_certificate(&alternate,"SYNTHETIC_NONCE",&cert,3000).is_ok());
        let mut l=license();l["tokenVersion"]=json!(2);let bad=token(&key,&cert,l,|_|{});assert_eq!(verify_with_certificate(&bad,"SYNTHETIC_NONCE",&cert,3000).err(),Some("token_version"));
        let mut l=license();let mut duplicate=l["licensableProducts"][0].clone();duplicate["endDate"]=json!("2041-01-01T00:00:00Z");l["licensableProducts"].as_array_mut().unwrap().push(duplicate);let bad=token(&key,&cert,l,|_|{});assert_eq!(verify_with_certificate(&bad,"SYNTHETIC_NONCE",&cert,3000).err(),Some("conflicting_duplicate_product"));
        let mut split:Vec<String>=good.split('.').map(String::from).collect();let mut sig=BASE64_URL_SAFE_NO_PAD.decode(&split[2]).unwrap();sig[0]^=1;split[2]=BASE64_URL_SAFE_NO_PAD.encode(sig);assert_eq!(verify_with_certificate(&split.join("."),"SYNTHETIC_NONCE",&cert,3000).err(),Some("signature_invalid"));
        assert_eq!(verify_with_certificate(&good,"SYNTHETIC_NONCE",&cert,11_000).err(),Some("certificate_expired"));
    }
}
