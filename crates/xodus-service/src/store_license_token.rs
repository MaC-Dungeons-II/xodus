//! Receipt acquisition, not an entitlement decision. The original Microsoft JWT
//! and caller challenge have no Debug implementations and must never be logged.
use crate::store_license::{acquire_msa_tokens, verified_token, Status};
use quick_xml::{events::Event, Reader};
use std::{sync::Arc, time::Duration};
use xodus::tokens::TokenManager;

pub const MAX_PRODUCTS: usize = 100;
pub const MAX_CHALLENGE: usize = 8192;
pub const MAX_TOKEN: usize = 60000;

#[derive(Clone)]
pub struct Request {
    pub context: String,
    pub store_id: String,
    pub product_ids: Vec<String>,
    pub custom_developer_string: String,
}

// The wrapper carries validity through the final account check and XML encoding.
// No token cache: each call, including repeated challenges, performs a new request.
pub struct Receipt { token: String, not_before: i64, expires_at: i64 }

#[derive(Default)]
struct Node { name: String, text: String, children: Vec<Node> }

fn xml_char(c: char) -> bool {
    matches!(c, '\t'|'\n'|'\r'|'\u{20}'..='\u{d7ff}'|'\u{e000}'..='\u{fffd}'|'\u{10000}'..='\u{10ffff}')
}
fn product_id(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
fn begin(stack: &mut Vec<Node>, name: &str, root_seen: bool) -> Result<(), Status> {
    let allowed = match stack.last().map(|n| n.name.as_str()) {
        None => !root_seen && name == "StoreLicenseTokenRequest",
        Some("StoreLicenseTokenRequest") => ["Context", "StoreId", "ProductIds", "CustomDeveloperString"].contains(&name),
        Some("ProductIds") => name == "ProductId" && stack.last().unwrap().children.len() < MAX_PRODUCTS,
        _ => false,
    };
    if !allowed { return Err(Status::InvalidRequest); }
    stack.push(Node { name: name.into(), ..Node::default() });
    Ok(())
}
fn end(stack: &mut Vec<Node>, root: &mut Option<Node>) -> Result<(), Status> {
    let node = stack.pop().ok_or(Status::InvalidRequest)?;
    if let Some(parent) = stack.last_mut() { parent.children.push(node); }
    else if root.replace(node).is_some() { return Err(Status::InvalidRequest); }
    Ok(())
}
fn text(stack: &mut [Node], value: &str) -> Result<(), Status> {
    if !value.chars().all(xml_char) { return Err(Status::InvalidRequest); }
    match stack.last_mut() {
        Some(node) if !["StoreLicenseTokenRequest", "ProductIds"].contains(&node.name.as_str()) => node.text.push_str(value),
        _ if value.chars().all(|c| matches!(c, ' '|'\t'|'\r'|'\n')) => (),
        _ => return Err(Status::InvalidRequest),
    }
    Ok(())
}

pub fn parse_request(input: &[u8]) -> Result<Request, Status> {
    if input.len() > u16::MAX as usize { return Err(Status::InvalidRequest); }
    let input = input.strip_suffix(&[0]).unwrap_or(input);
    let input = std::str::from_utf8(input).map_err(|_| Status::InvalidRequest)?;
    if input.is_empty() || input.contains('\0') { return Err(Status::InvalidRequest); }
    let mut reader = Reader::from_str(input);
    let mut stack = Vec::new();
    let mut root = None;
    loop {
        match reader.read_event().map_err(|_| Status::InvalidRequest)? {
            Event::Start(e) => {
                if e.attributes().next().is_some() { return Err(Status::InvalidRequest); }
                begin(&mut stack, e.name().as_ref(), root.is_some())?;
            },
            Event::Empty(e) => {
                if e.attributes().next().is_some() { return Err(Status::InvalidRequest); }
                begin(&mut stack, e.name().as_ref(), root.is_some())?;
                end(&mut stack, &mut root)?;
            },
            Event::End(_) => end(&mut stack, &mut root)?,
            // Deliberately preserve whitespace/UTF-8 exactly. The native encoder
            // represents CR as &#13;, so XML line-ending conversion cannot alter it.
            Event::Text(t) => text(&mut stack, t.as_ref())?,
            Event::GeneralRef(r) => {
                let ch = match r.resolve_char_ref().map_err(|_| Status::InvalidRequest)? {
                    Some(ch) => ch,
                    None => match r.as_ref() { "amp" => '&', "lt" => '<', "gt" => '>', "quot" => '"', "apos" => '\'', _ => return Err(Status::InvalidRequest) },
                };
                text(&mut stack, ch.encode_utf8(&mut [0; 4]))?;
            },
            Event::Eof => break,
            // No DTD/entity declarations, namespaces, comments, PI or CDATA.
            _ => return Err(Status::InvalidRequest),
        }
    }
    if !stack.is_empty() { return Err(Status::InvalidRequest); }
    let root = root.ok_or(Status::InvalidRequest)?;
    let mut fields = std::collections::BTreeMap::new();
    for node in root.children {
        if fields.insert(node.name.clone(), node).is_some() { return Err(Status::InvalidRequest); }
    }
    if fields.len() != 4 { return Err(Status::InvalidRequest); }
    let context = fields.remove("Context").ok_or(Status::InvalidRequest)?.text;
    let store_id = fields.remove("StoreId").ok_or(Status::InvalidRequest)?.text;
    let product_ids = fields.remove("ProductIds").ok_or(Status::InvalidRequest)?.children.into_iter().map(|n| n.text).collect::<Vec<_>>();
    let custom_developer_string = fields.remove("CustomDeveloperString").ok_or(Status::InvalidRequest)?.text;
    if context.len() != 64 || !context.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !product_id(&store_id) || !product_ids.iter().all(|s| product_id(s))
        || custom_developer_string.is_empty() || custom_developer_string.len() > MAX_CHALLENGE {
        return Err(Status::InvalidRequest);
    }
    Ok(Request { context, store_id, product_ids, custom_developer_string })
}

pub async fn query(request: Request, tokens: Arc<TokenManager>) -> Result<Receipt, Status> {
    let mut worker = tokio::task::JoinSet::new();
    worker.spawn(async move { acquire(&request, &tokens).await });
    match tokio::time::timeout(Duration::from_secs(35), worker.join_next()).await {
        Ok(Some(Ok(result))) => result,
        Ok(_) => Err(Status::Error),
        Err(_) => {
            worker.abort_all();
            while worker.join_next().await.is_some() {}
            Err(Status::Timeout)
        },
    }
}

async fn acquire(request: &Request, tokens: &TokenManager) -> Result<Receipt, Status> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_| Status::Error)?;
    let (device, user, puid) = acquire_msa_tokens(&client, tokens).await?;
    // Forward order, duplicates and the exact developer string. Never substitute
    // GameLicense's generated nonce or silently add the parent to this array.
    for attempt in 0..3 {
        let token = xodus::licensing::content::get_license_token(&client, device.clone(), user.clone(), puid.clone(),
            request.store_id.clone(), request.product_ids.clone(), request.custom_developer_string.clone())
            .await.map_err(|_| Status::Error)?;
        if !wire_token(&token) { return Err(Status::Error); }
        let verified = verified_token::verify(&client, &token, &request.custom_developer_string).await
            .map_err(|stage| { tracing::warn!(stage, "Store receipt verification failed"); Status::Error })?;
        let now = chrono::Utc::now().timestamp();
        // Diagnostics: catalogue IDs and grant state only (no token, account or nonce).
        let granted: Vec<String> = verified.products.iter().map(|p| format!("{}/{} active={}", p.product_id, p.sku_id, p.ends_at > now)).collect();
        eprintln!("store-license-token: store_id={} requested={:?} granted={:?}", request.store_id, request.product_ids, granted);
        let result = receipt(token, &verified, request, now)?;
        // Downloads can race the service's license renewal. Repeat the real
        // read for explicitly requested products with only expired grants.
        // Never alter the signed receipt, retry missing ownership, or cache a
        // developer challenge. The existing deadline/cancellation bounds us.
        if attempt==2 || !needs_refresh(&verified, request, now) { return Ok(result); }
        tokio::time::sleep(Duration::from_millis(if attempt==0 {350} else {1000})).await;
    }
    Err(Status::Error)
}

fn needs_refresh(verified:&verified_token::VerifiedToken, request:&Request, now:i64)->bool {
    request.product_ids.iter().any(|id| {
        verified.products.iter().any(|p| &p.product_id==id && p.ends_at<=now) &&
        !verified.products.iter().any(|p| &p.product_id==id && p.ends_at>now)
    })
}

fn wire_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_TOKEN && token.split('.').count() == 3
        && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.'|b'_'|b'-'))
}
fn receipt(token: String, verified: &verified_token::VerifiedToken, request: &Request, now: i64) -> Result<Receipt, Status> {
    if now < verified.not_before || now >= verified.expires_at { return Err(Status::Expired); }
    // The documented endpoint receives a parent plus related products. Accept
    // either, but never introduce unrelated signed products into this request.
    if verified.products.iter().any(|p| p.product_id != request.store_id && !request.product_ids.contains(&p.product_id)) { return Err(Status::Error); }
    // Empty/partial entitlements and trials are legitimate receipt contents. The
    // game's service evaluates the unmodified signed claims; no catalogue mapping.
    Ok(Receipt { token, not_before: verified.not_before, expires_at: verified.expires_at })
}

pub fn encode(result: Result<Receipt, Status>) -> Vec<u8> {
    let now = chrono::Utc::now().timestamp();
    let result = result.and_then(|r| {
        if now < r.not_before || now >= r.expires_at { Err(Status::Expired) }
        else if !wire_token(&r.token) { Err(Status::Error) }
        else { Ok(r) }
    });
    let body = match result {
        Ok(r) => format!("<Status>Available</Status><Token>{}</Token>", r.token),
        Err(status) => format!("<Status>{status:?}</Status>"),
    };
    format!("<StoreLicenseTokenResponse>{body}</StoreLicenseTokenResponse>").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn xml(challenge: &str, ids: &str) -> String {
        format!("<StoreLicenseTokenRequest><Context>{}</Context><StoreId>ABCD1234EFGH</StoreId><ProductIds>{ids}</ProductIds><CustomDeveloperString>{challenge}</CustomDeveloperString></StoreLicenseTokenRequest>", "a".repeat(64))
    }
    #[test]
    fn exact_challenge_and_product_list_roundtrip() {
        let r = parse_request(xml("  &amp;&lt;&gt;&quot;&apos;&#13;\n\t Österreich 🛫  ", "<ProductId>ABCD1234EFGH</ProductId><ProductId>OTHER1234567</ProductId><ProductId>ABCD1234EFGH</ProductId>").as_bytes()).unwrap();
        assert_eq!(r.custom_developer_string, "  &<>\"'\r\n\t Österreich 🛫  ");
        assert_eq!(r.product_ids, ["ABCD1234EFGH", "OTHER1234567", "ABCD1234EFGH"]);
        assert!(parse_request(xml("valid", "").as_bytes()).unwrap().product_ids.is_empty());
        assert!(parse_request(xml("valid", "").replace("<ProductIds></ProductIds>", "<ProductIds/>").as_bytes()).is_ok());
        assert!(parse_request(format!("{}\0", xml("valid", "")).as_bytes()).is_ok());
    }
    #[test]
    fn malformed_schema_is_status_only() {
        let good = xml("synthetic", "<ProductId>ABCD1234EFGH</ProductId>");
        for bad in [good.replace("synthetic", ""), good.replace("synthetic", "&#0;"), good.replace("synthetic", "&#1;"), good.replace("synthetic", "&unknown;"), good.replace("synthetic", "\u{1}"), good.replace("synthetic", "<![CDATA[value]]>"), good.replace("<StoreId>", "<StoreId x='1'>"), good.replace("</StoreId>", "</StoreId><StoreId>ABCD1234EFGH</StoreId>"), good.replace("<ProductId>", "<Unexpected>"), good.replace("<ProductIds>", "<ProductIds>text"), good.replace("ABCD1234EFGH", "../escape"), format!("<!DOCTYPE x>{good}"), format!("{good}{good}"), format!("{good}\0\0"), good.replace("synthetic", &"x".repeat(MAX_CHALLENGE + 1)), good.replace("<ProductId>ABCD1234EFGH</ProductId>", &"<ProductId>ABCD1234EFGH</ProductId>".repeat(MAX_PRODUCTS + 1))] {
            assert!(matches!(parse_request(bad.as_bytes()), Err(Status::InvalidRequest)));
        }
        for status in [Status::Unavailable, Status::Expired, Status::NotLicensed, Status::Unsupported, Status::InvalidRequest, Status::Error, Status::Timeout] {
            assert_eq!(String::from_utf8(encode(Err(status))).unwrap(), format!("<StoreLicenseTokenResponse><Status>{status:?}</Status></StoreLicenseTokenResponse>"));
        }
    }
    #[test]
    fn opaque_receipt_partial_empty_time_and_output_bounds() {
        let request = parse_request(xml("test", "<ProductId>OTHER1234567</ProductId>").as_bytes()).unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut verified = verified_token::VerifiedToken { products: vec![], not_before: now - 1, expires_at: now + 100 };
        let original = "eyJTest.Exact_Payload.Signature-123".to_string();
        let encoded = encode(receipt(original.clone(), &verified, &request, now));
        assert_eq!(encoded, format!("<StoreLicenseTokenResponse><Status>Available</Status><Token>{original}</Token></StoreLicenseTokenResponse>").as_bytes());
        // A signed expired product still belongs in the receipt for the server.
        verified.products.push(verified_token::Product { product_id: "OTHER1234567".into(), sku_id: "0001".into(), ends_at: 0 });
        assert!(receipt(original.clone(), &verified, &request, now).is_ok());
        assert!(matches!(receipt(original.clone(), &verified, &request, now + 100), Err(Status::Expired)));
        verified.products[0].product_id = "UNRELATED123".into();
        assert!(matches!(receipt(original, &verified, &request, now), Err(Status::Error)));
        assert!(!wire_token("a.b.<")); assert!(!wire_token("a.b.c\0")); assert!(!wire_token(&format!("a.b.{}", "a".repeat(MAX_TOKEN))));
        let max = format!("a.b.{}", "a".repeat(MAX_TOKEN - 4));
        assert!(encode(Ok(Receipt { token: max, not_before: now - 1, expires_at: now + 100 })).len() <= u16::MAX as usize);
        assert!(String::from_utf8(encode(Ok(Receipt { token: "a.b.c".into(), not_before: now - 100, expires_at: now }))).unwrap().contains("<Status>Expired</Status>"));
    }
    #[tokio::test]
    async fn missing_broker_never_returns_cached_receipt() {
        let tokens = Arc::new(TokenManager::with_memory());
        for challenge in ["first", "second"] {
            assert!(matches!(query(parse_request(xml(challenge, "").as_bytes()).unwrap(), tokens.clone()).await, Err(Status::Unavailable)));
        }
    }
    #[test]
    fn refresh_only_expired_requested_products_without_a_valid_alternative() {
        let request=parse_request(xml("same-challenge","<ProductId>OTHER1234567</ProductId>").as_bytes()).unwrap();
        let mut verified=verified_token::VerifiedToken {products:vec![],not_before:0,expires_at:1000};
        assert!(!needs_refresh(&verified,&request,100));
        verified.products.push(verified_token::Product {product_id:request.store_id.clone(),sku_id:"0001".into(),ends_at:1});
        assert!(!needs_refresh(&verified,&request,100));
        verified.products.push(verified_token::Product {product_id:"OTHER1234567".into(),sku_id:"0001".into(),ends_at:100});
        assert!(needs_refresh(&verified,&request,100));
        verified.products.push(verified_token::Product {product_id:"OTHER1234567".into(),sku_id:"0002".into(),ends_at:101});
        assert!(!needs_refresh(&verified,&request,100));
    }
}
