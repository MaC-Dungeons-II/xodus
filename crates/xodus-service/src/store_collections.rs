//! Account-bound, read-only exact-SKU consumer Collections evidence.
//! Shared entitlements and whole-title inventory are intentionally not asserted.
pub(crate) mod auth;
pub(crate) mod model;
use crate::store_license::Status;
use model::{Request, Snapshot, Wanted};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use xodus::tokens::TokenManager;

#[derive(Deserialize)]
#[serde(
    rename = "StoreCollectionsRequest",
    rename_all = "PascalCase",
    deny_unknown_fields
)]
struct WireRequest {
    context: String,
    store_id: String,
    title_id: u32,
    msa_app_id: String,
    products: Products,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Products {
    #[serde(rename = "Product", default)]
    items: Vec<Product>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Product {
    store_id: String,
    kind: u32,
}

pub fn parse_request(bytes: &[u8]) -> Result<Request, Status> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() || bytes.len() > 16384 || bytes.contains(&0) {
        return Err(Status::InvalidRequest);
    }
    let mut reader = Reader::from_reader(bytes);
    let mut stack = Vec::<String>::new();
    let mut root = false;
    loop {
        match reader.read_event().map_err(|_| Status::InvalidRequest)? {
            Event::Start(e) => {
                let name = e.name().as_ref().to_string();
                let allowed = match stack.last().map(String::as_str) {
                    None => !root && name == "StoreCollectionsRequest",
                    Some("StoreCollectionsRequest") => {
                        ["Context", "StoreId", "TitleId", "MsaAppId", "Products"]
                            .contains(&name.as_str())
                    }
                    Some("Products") => name == "Product",
                    Some("Product") => ["StoreId", "Kind"].contains(&name.as_str()),
                    _ => false,
                };
                if !allowed || e.attributes().next().is_some() {
                    return Err(Status::InvalidRequest);
                }
                if stack.is_empty() {
                    root = true;
                }
                stack.push(name);
            }
            Event::End(_) => {
                stack.pop().ok_or(Status::InvalidRequest)?;
            }
            Event::Text(t) => {
                if !matches!(
                    stack.last().map(String::as_str),
                    Some("Context" | "StoreId" | "TitleId" | "MsaAppId" | "Kind")
                ) && !t.as_ref().chars().all(|c| c.is_ascii_whitespace())
                {
                    return Err(Status::InvalidRequest);
                }
            }
            Event::Eof => break,
            _ => return Err(Status::InvalidRequest),
        }
    }
    if !root || !stack.is_empty() {
        return Err(Status::InvalidRequest);
    }
    let wire: WireRequest =
        quick_xml::de::from_reader(bytes).map_err(|_| Status::InvalidRequest)?;
    let request = Request {
        context: wire.context,
        store_id: wire.store_id,
        title_id: wire.title_id,
        msa_app_id: wire.msa_app_id,
        products: wire
            .products
            .items
            .into_iter()
            .map(|p| Wanted {
                store_id: p.store_id,
                kind: p.kind,
            })
            .collect(),
    };
    model::validate(&request)?;
    Ok(request)
}

#[derive(Default)]
pub struct Broker {
    session: Option<auth::Session>,
}
fn query_body(request: &Request, batch: &[Wanted]) -> Value {
    // Product-wide filters cover every requested SKU. Mixing entries with and
    // without the optional skuId was observed to fail with HTTP400; using only
    // documented productId filters also keeps the parent control independent of
    // the caller's selected SKU. Exact matching happens only after full paging.
    let mut products = batch
        .iter()
        .map(|p| &p.store_id[..12])
        .collect::<BTreeSet<_>>();
    products.insert(&request.store_id);
    let ids = products
        .into_iter()
        .map(|id| json!({"productId":id}))
        .collect::<Vec<_>>();
    json!({"market":"neutral","validityType":"All","maxPageSize":100,"excludeDuplicates":true,"expandSatisfyingItems":true,"entitlementFilters":["*:Game","*:Durable","*:Pass","*:Consumable","*:UnmanagedConsumable"],"productSkuIds":ids})
}
impl Broker {
    pub fn clear(&mut self) {
        self.session = None;
    }
    pub async fn query(
        &mut self,
        request: &Request,
        tokens: Arc<TokenManager>,
    ) -> Result<Snapshot, Status> {
        // Cancellation drops all reqwest work; no detached query or token request.
        match tokio::time::timeout(Duration::from_secs(35), self.query_inner(request, &tokens))
            .await
        {
            Ok(result) => result,
            Err(_) => {
                self.clear();
                Err(Status::Timeout)
            }
        }
    }
    async fn query_inner(
        &mut self,
        request: &Request,
        tokens: &TokenManager,
    ) -> Result<Snapshot, Status> {
        model::validate(request)?;
        if !self.session.as_ref().is_some_and(|s| s.matches(request)) {
            self.session = None;
            self.session = Some(auth::Session::create(request, tokens).await?);
        }
        let session = self.session.as_mut().ok_or(Status::Error)?;
        let mut records = Vec::new();
        let mut expires = session.expires_at;
        // At most 99 requested product IDs plus the parent control per HTTP query.
        // The extra control is not returned as a requested product to the caller.
        for batch in request.products.chunks(99) {
            let mut body = query_body(request, batch);
            let mut batch_pages = model::BatchPages::default();
            loop {
                let page = model::parse_page(&session.page(&body).await?)?;
                if let Some(cursor) = batch_pages.push(page)? {
                    body["continuationToken"] = Value::String(cursor);
                } else {
                    break;
                }
            }
            let (batch_records, parent_expiry) =
                batch_pages.finish(&request.store_id, chrono::Utc::now().timestamp())?;
            if records.len() + batch_records.len() > 1000 {
                return Err(Status::Unsupported);
            }
            expires = expires.min(parent_expiry);
            records.extend(batch_records);
        }
        model::finish(request, records, chrono::Utc::now().timestamp(), expires)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct WireItem<'a> {
    store_id: &'a str,
    kind: u32,
    acquired_date: i64,
    start_date: i64,
    end_date: i64,
    quantity: u32,
    is_trial: bool,
    trial_time_remaining_in_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    campaign_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    developer_offer_id: Option<&'a str>,
}
pub fn encode(result: Result<Snapshot, Status>) -> Vec<u8> {
    fn inner(s: Snapshot) -> Result<String, Status> {
        let now = chrono::Utc::now().timestamp();
        if s.observed_at > now || s.expires_at <= now {
            return Err(Status::Expired);
        }
        let mut body = format!(
            "<Status>Available</Status><ContextBound>true</ContextBound><Complete>true</Complete><DirectCoverage>true</DirectCoverage><SatisfyingCoverage>true</SatisfyingCoverage><SharedCoverage>false</SharedCoverage><ParentControlActive>true</ParentControlActive><ObservedAt>{}</ObservedAt><ExpiresAt>{}</ExpiresAt><Items>",
            s.observed_at, s.expires_at
        );
        for i in &s.items {
            let item = WireItem {
                store_id: &i.store_id,
                kind: i.kind,
                acquired_date: i.acquired_date,
                start_date: i.start_date,
                end_date: i.end_date,
                quantity: i.quantity,
                is_trial: i.is_trial,
                trial_time_remaining_in_seconds: i.trial_time_remaining_in_seconds,
                campaign_id: i.campaign_id.as_deref(),
                developer_offer_id: i.developer_offer_id.as_deref(),
            };
            let xml =
                quick_xml::se::to_string_with_root("Item", &item).map_err(|_| Status::Error)?;
            body.push_str(&xml);
        }
        body.push_str("</Items><AbsentIds>");
        for id in s.absent {
            body.push_str(&format!("<StoreId>{id}</StoreId>"));
        }
        body.push_str("</AbsentIds><UnknownIds>");
        for id in s.unknown {
            body.push_str(&format!("<StoreId>{id}</StoreId>"));
        }
        body.push_str("</UnknownIds>");
        if body.len() + 64 > u16::MAX as usize {
            return Err(Status::Unsupported);
        }
        Ok(body)
    }
    let body = match result.and_then(inner) {
        Ok(body) => body,
        Err(status) => format!("<Status>{status:?}</Status>"),
    };
    format!("<StoreCollectionsResponse>{body}</StoreCollectionsResponse>").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn xml() -> String {
        format!(
            "<StoreCollectionsRequest><Context>{}</Context><StoreId>ABCD1234EFGH</StoreId><TitleId>1</TitleId><MsaAppId>00000000-1111-2222-3333-444444444444</MsaAppId><Products><Product><StoreId>COIN1234EFGH/0001</StoreId><Kind>16</Kind></Product></Products></StoreCollectionsRequest>",
            "a".repeat(64)
        )
    }
    #[test]
    fn strict_wire_and_duplicates() {
        assert_eq!(parse_request(xml().as_bytes()).unwrap().products.len(), 1);
        assert!(parse_request(format!("{}\0", xml()).as_bytes()).is_ok());
        for bad in [
            xml().replace("<Kind>16</Kind>", "<Kind>31</Kind>"),
            xml().replace(
                "<TitleId>1</TitleId>",
                "<TitleId>1</TitleId><TitleId>2</TitleId>",
            ),
            xml().replace("<Products>", "<Products attr='1'>"),
            xml().replace("<Kind>16</Kind>", "<Kind>16</Kind><X>1</X>"),
            format!("<!DOCTYPE x>{}", xml()),
            format!("{}\0\0", xml()),
            xml().replace("COIN1234EFGH/0001", "COIN1234EFGH"),
        ] {
            assert!(parse_request(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn expired_and_error_responses_are_status_only() {
        let now = chrono::Utc::now().timestamp();
        let s = Snapshot {
            items: vec![],
            absent: vec![],
            unknown: vec![],
            observed_at: now,
            expires_at: now,
        };
        assert_eq!(
            encode(Ok(s)),
            b"<StoreCollectionsResponse><Status>Expired</Status></StoreCollectionsResponse>"
        );
        assert_eq!(
            encode(Err(Status::Unavailable)),
            b"<StoreCollectionsResponse><Status>Unavailable</Status></StoreCollectionsResponse>"
        );
    }
    #[test]
    fn exact_query_has_satisfying_and_unique_parent_control() {
        let request = parse_request(xml().as_bytes()).unwrap();
        let body = query_body(&request, &request.products);
        assert_eq!(body["expandSatisfyingItems"], true);
        assert_eq!(body["productSkuIds"].as_array().unwrap().len(), 2);
        assert!(
            body["productSkuIds"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p.get("skuId").is_none())
        );
        let parent = Wanted {
            store_id: format!("{}/0001", request.store_id),
            kind: 4,
        };
        let body = query_body(
            &request,
            &[
                parent.clone(),
                Wanted {
                    store_id: format!("{}/0002", request.store_id),
                    kind: 4,
                },
            ],
        );
        assert_eq!(body["productSkuIds"].as_array().unwrap().len(), 1);
        assert_eq!(body["productSkuIds"][0]["productId"], request.store_id);
    }
}
