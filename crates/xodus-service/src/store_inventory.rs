//! Current Store account's direct and satisfying entitlements for this title.
//! Exhaust the authenticated library before filtering; catalog visibility is
//! never evidence of ownership. Device-shared entitlements are not covered.
use crate::store_collections::{
    auth,
    model::{self, Item, Record, Snapshot},
};
use crate::store_license::{self, Status};
use quick_xml::{Reader, events::Event};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
use xodus::tokens::TokenManager;

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(
    rename = "StoreInventoryRequest",
    rename_all = "PascalCase",
    deny_unknown_fields
)]
pub struct Request {
    pub context: String,
    pub store_id: String,
    pub title_id: u32,
    pub msa_app_id: String,
    pub market: String,
    pub kinds: u32,
    pub page_size: usize,
    #[serde(default)]
    pub continuation: String,
}
fn context_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn parse_request(bytes: &[u8]) -> Result<Request, Status> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() || bytes.len() > 2048 || bytes.contains(&0) {
        return Err(Status::InvalidRequest);
    }
    let mut reader = Reader::from_reader(bytes);
    let mut depth = 0;
    let mut root = false;
    loop {
        match reader.read_event().map_err(|_| Status::InvalidRequest)? {
            Event::Start(e) => {
                if e.attributes().next().is_some() || depth > 1 {
                    return Err(Status::InvalidRequest);
                }
                if depth == 0 {
                    if root || e.name().as_ref() != "StoreInventoryRequest" {
                        return Err(Status::InvalidRequest);
                    }
                    root = true;
                } else if ![
                    "Context",
                    "StoreId",
                    "TitleId",
                    "MsaAppId",
                    "Market",
                    "Kinds",
                    "PageSize",
                    "Continuation",
                ]
                .contains(&e.name().as_ref())
                {
                    return Err(Status::InvalidRequest);
                }
                depth += 1;
            }
            Event::End(_) => {
                if depth == 0 {
                    return Err(Status::InvalidRequest);
                }
                depth -= 1;
            }
            Event::Text(t) if depth == 2 || t.as_ref().chars().all(|c| c.is_ascii_whitespace()) => {
                ()
            }
            Event::Eof => break,
            _ => return Err(Status::InvalidRequest),
        }
    }
    if !root || depth != 0 {
        return Err(Status::InvalidRequest);
    }
    let r: Request = quick_xml::de::from_reader(bytes).map_err(|_| Status::InvalidRequest)?;
    if !context_id(&r.context)
        || !model::valid_id(&r.store_id, 12)
        || r.title_id == 0
        || !model::valid_app_id(&r.msa_app_id)
        || r.market.len() != 2
        || !r.market.bytes().all(|c| c.is_ascii_uppercase())
        || r.kinds == 0
        || r.kinds & !31 != 0
        || !(1..=100).contains(&r.page_size)
        || (!r.continuation.is_empty() && !context_id(&r.continuation))
    {
        return Err(Status::InvalidRequest);
    }
    Ok(r)
}
pub struct Page {
    pub snapshot: Snapshot,
    pub continuation: String,
}
struct Pending {
    request: Request,
    items: Vec<Item>,
    observed_at: i64,
    expires_at: i64,
    created: Instant,
    cursor: String,
    offset: usize,
}
#[derive(Default)]
pub struct Broker {
    pending: Vec<Pending>,
}
impl Broker {
    pub fn clear(&mut self) {
        self.pending.clear();
    }
    pub async fn query(&mut self, r: &Request, tokens: Arc<TokenManager>) -> Result<Page, Status> {
        self.pending.retain(|p| {
            p.created.elapsed() < Duration::from_secs(30)
                && p.expires_at > chrono::Utc::now().timestamp()
        });
        if !r.continuation.is_empty() {
            let index = self
                .pending
                .iter()
                .position(|p| p.cursor == r.continuation && same_query(&p.request, r))
                .ok_or(Status::Expired)?;
            let result = take_page(&mut self.pending[index]);
            self.pending.retain(|p| p.offset < p.items.len());
            return result;
        }
        let pending = tokio::time::timeout(Duration::from_secs(35), collect(r, tokens))
            .await
            .map_err(|_| Status::Timeout)??;
        if self.pending.len() >= 8 {
            return Err(Status::Unavailable);
        }
        self.pending.push(pending);
        let result = take_page(self.pending.last_mut().ok_or(Status::Error)?);
        self.pending.retain(|p| p.offset < p.items.len());
        result
    }
}
fn same_query(a: &Request, b: &Request) -> bool {
    a.context == b.context
        && a.store_id == b.store_id
        && a.title_id == b.title_id
        && a.msa_app_id == b.msa_app_id
        && a.market == b.market
        && a.kinds == b.kinds
        && a.page_size == b.page_size
}
fn token() -> String {
    rand::random::<[u8; 32]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn take_page(p: &mut Pending) -> Result<Page, Status> {
    let now = chrono::Utc::now().timestamp();
    if p.expires_at <= now || p.observed_at > now || p.created.elapsed() >= Duration::from_secs(30)
    {
        return Err(Status::Expired);
    }
    let start = p.offset;
    let mut end = start;
    let mut products = BTreeSet::new();
    while end < p.items.len() {
        let id = &p.items[end].store_id[..12];
        let mut group_end = end + 1;
        while group_end < p.items.len() && &p.items[group_end].store_id[..12] == id { group_end += 1; }
        if products.len() == p.request.page_size || group_end - start > 100 { break; }
        products.insert(id.to_owned());
        end = group_end;
    }
    if end == start && start < p.items.len() { return Err(Status::Unsupported); }
    let continuation = if end < p.items.len() {
        token()
    } else {
        String::new()
    };
    let page = Page {
        snapshot: Snapshot {
            items: p.items[start..end].to_vec(),
            absent: vec![],
            unknown: vec![],
            observed_at: p.observed_at,
            expires_at: p.expires_at,
        },
        continuation: continuation.clone(),
    };
    // Only advance after proving that the complete frame fits the IPC contract.
    encode_page(&page)?;
    p.offset = end;
    p.cursor = continuation;
    Ok(page)
}
fn active_items(records: Vec<Record>, kinds: u32, now: i64) -> Result<Vec<Item>, Status> {
    let mut items = BTreeMap::<String, Item>::new();
    for r in records {
        if !r.active
            || r.item.end_date <= now
            || r.item.start_date > now
            || r.item.kind & kinds == 0
        {
            continue;
        }
        if r.item.acquired_date > now {
            return Err(Status::Unsupported);
        }
        if let Some(old) = items.get(&r.item.store_id) {
            if old != &r.item {
                return Err(Status::Unsupported);
            }
        } else {
            items.insert(r.item.store_id.clone(), r.item);
        }
    }
    Ok(items.into_values().collect())
}
fn associated(value: &Value, product: &str, parent: &str) -> Result<bool, Status> {
    let p = &value["Product"];
    if p["ProductId"].as_str() != Some(product) {
        return Err(Status::Unsupported);
    }
    if product == parent {
        return Ok(true);
    }
    let markets = p["MarketProperties"]
        .as_array()
        .ok_or(Status::Unsupported)?;
    for market in markets {
        let related = market["RelatedProducts"]
            .as_array()
            .ok_or(Status::Unsupported)?;
        for r in related {
            if r["RelatedProductId"].as_str() == Some(parent)
                && r["RelationshipType"].as_str() == Some("addOnParent")
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn page_envelope(raw: &Value) -> Result<(BTreeSet<String>, Option<String>, usize), Status> {
    let rows = raw["items"].as_array().filter(|v| v.len() <= 100).ok_or(Status::Unsupported)?;
    let mut ids = BTreeSet::new();
    for row in rows {
        let id = row["productId"].as_str().filter(|s| model::valid_id(s, 12)).ok_or(Status::Unsupported)?;
        ids.insert(id.to_owned());
    }
    // Reuse the strict page-envelope parser, with no rights interpreted yet.
    let mut envelope = raw.clone(); envelope["items"] = json!([]);
    let continuation = model::parse_page(&envelope)?.continuation;
    Ok((ids, continuation, rows.len()))
}
fn scoped_page(mut raw: Value, allowed: &BTreeSet<String>) -> Result<model::Page, Status> {
    page_envelope(&raw)?;
    raw["items"].as_array_mut().ok_or(Status::Unsupported)?.retain(|row|
        row["productId"].as_str().is_some_and(|id| allowed.contains(id)));
    model::parse_page(&raw)
}
async fn collect(r: &Request, tokens: Arc<TokenManager>) -> Result<Pending, Status> {
    let binding = model::Request {
        context: r.context.clone(),
        store_id: r.store_id.clone(),
        title_id: r.title_id,
        msa_app_id: r.msa_app_id.clone(),
        products: vec![],
    };
    let mut session = auth::Session::create(&binding, &tokens).await?;
    let mut body = json!({"market":"neutral","validityType":"All","maxPageSize":100,"excludeDuplicates":true,"expandSatisfyingItems":true,"entitlementFilters":["*:Game","*:Durable","*:Pass","*:Consumable","*:UnmanagedConsumable"]});
    // Establish title scope before interpreting rights. An unsupported trial or
    // sharing record for another game must not invalidate this game's Store.
    // All raw pages and IDs are still validated and exhausted first.
    let mut raw_pages = Vec::new();
    let mut roots = BTreeSet::new();
    let mut cursors = BTreeSet::new();
    let mut total = 0;
    loop {
        let raw = session.page(&body).await?;
        let (ids, continuation, count) = page_envelope(&raw)?;
        total += count;
        if raw_pages.len() >= 20 || total > 1000 { return Err(Status::Unsupported); }
        roots.extend(ids);
        raw_pages.push(raw);
        if let Some(cursor) = continuation {
            if !cursors.insert(cursor.clone()) || raw_pages.len() == 20 { return Err(Status::Unsupported); }
            body["continuationToken"] = Value::String(cursor);
        } else { break; }
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Status::Error)?;
    let mut allowed = BTreeSet::new();
    let mut workers = tokio::task::JoinSet::new();
    let mut roots = roots.into_iter();
    loop {
        while workers.len() < 4 {
            let Some(product) = roots.next() else {
                break;
            };
            let client = client.clone();
            let market = r.market.clone();
            let parent = r.store_id.clone();
            workers.spawn(async move {
                let value = store_license::fetch_catalogue(&client, &product, &market).await?;
                Ok::<_, Status>((product.clone(), associated(&value, &product, &parent)?))
            });
        }
        match workers.join_next().await {
            Some(result) => {
                let (id, yes) = result.map_err(|_| Status::Error)??;
                if yes {
                    allowed.insert(id);
                }
            }
            None => break,
        }
    }
    let now = chrono::Utc::now().timestamp();
    let mut pages = model::BatchPages::default();
    for raw in raw_pages { pages.push(scoped_page(raw, &allowed)?)?; }
    let (records, parent_expiry) = pages.finish(&r.store_id, now)?;
    let items = active_items(records, r.kinds, now)?;
    let expires_at = items.iter().map(|i| i.end_date).fold(
        session.expires_at.min(parent_expiry).min(now + 30),
        i64::min,
    );
    if expires_at <= now {
        return Err(Status::Expired);
    }
    Ok(Pending {
        request: r.clone(),
        items,
        observed_at: now,
        expires_at,
        created: Instant::now(),
        cursor: String::new(),
        offset: 0,
    })
}
fn encode_page(p: &Page) -> Result<Vec<u8>, Status> {
    let s = Snapshot {
        items: p.snapshot.items.clone(),
        absent: vec![],
        unknown: vec![],
        observed_at: p.snapshot.observed_at,
        expires_at: p.snapshot.expires_at,
    };
    let xml =
        String::from_utf8(crate::store_collections::encode(Ok(s))).map_err(|_| Status::Error)?;
    if !xml.contains("<Status>Available</Status>") {
        return Err(Status::Expired);
    }
    let xml = xml.replace(
        "</StoreCollectionsResponse>",
        &format!(
            "<Continuation>{}</Continuation></StoreCollectionsResponse>",
            p.continuation
        ),
    );
    if xml.len() > u16::MAX as usize {
        return Err(Status::Unsupported);
    }
    Ok(xml.into_bytes())
}
pub fn encode(result: Result<Page, Status>) -> Vec<u8> {
    match result.and_then(|p| encode_page(&p)) {
        Ok(bytes) => bytes,
        Err(status) => crate::store_collections::encode(Err(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_library_rights_do_not_poison_title_inventory() {
        let raw = json!({"items":[{"productId":"OTHER1234567","trialData":{"newServerShape":true}}],"continuationToken":"next"});
        let allowed = BTreeSet::from(["TITLE1234567".into()]);
        let page = scoped_page(raw.clone(), &allowed).unwrap();
        assert!(page.records.is_empty()); assert_eq!(page.continuation.as_deref(), Some("next"));
        assert!(scoped_page(raw, &BTreeSet::from(["OTHER1234567".into()])).is_err());
        assert!(page_envelope(&json!({"items":[{"productId":"invalid"}]})).is_err());
        assert!(page_envelope(&json!({"items":[],"continuationToken":42})).is_err());
    }

    fn request() -> Request {
        Request {
            context: "a".repeat(64),
            store_id: "GAME1234EFGH".into(),
            title_id: 1,
            msa_app_id: "00000000-1111-2222-3333-444444444444".into(),
            market: "US".into(),
            kinds: 2,
            page_size: 1,
            continuation: String::new(),
        }
    }
    fn item(id: &str) -> Item {
        Item {
            store_id: id.into(),
            kind: 2,
            acquired_date: 1,
            start_date: 1,
            end_date: i64::MAX,
            quantity: 1,
            is_trial: false,
            trial_time_remaining_in_seconds: 0,
            campaign_id: None,
            developer_offer_id: None,
        }
    }
    #[test]
    fn entitled_items_ignore_expired_and_reject_conflicts() {
        let good = item("ADDN1234EFGH/0001");
        let mut expired = good.clone();
        expired.end_date = 2;
        let result = active_items(
            vec![
                Record {
                    item: good.clone(),
                    active: true,
                },
                Record {
                    item: expired,
                    active: true,
                },
            ],
            2,
            3,
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        let mut other = good.clone();
        other.acquired_date = 2;
        assert!(
            active_items(
                vec![
                    Record {
                        item: good,
                        active: true
                    },
                    Record {
                        item: other,
                        active: true
                    }
                ],
                2,
                3
            )
            .is_err()
        );
    }
    #[test]
    fn title_association_is_exact_and_independent_of_purchase_visibility() {
        let v = json!({"Product":{"ProductId":"ADDN1234EFGH","MarketProperties":[{"RelatedProducts":[{"RelationshipType":"addOnParent","RelatedProductId":"GAME1234EFGH"}]}]}});
        assert!(associated(&v, "ADDN1234EFGH", "GAME1234EFGH").unwrap());
        assert!(!associated(&v, "ADDN1234EFGH", "OTHR1234EFGH").unwrap());
        assert!(associated(&v, "OTHR1234EFGH", "GAME1234EFGH").is_err());
    }
    #[test]
    fn pages_keep_product_skus_together_and_expire() {
        let now = chrono::Utc::now().timestamp();
        let mut p = Pending {
            request: request(),
            items: vec![
                item("ADDN1234EFGH/0001"),
                item("ADDN1234EFGH/0002"),
                item("NEXT1234EFGH/0001"),
            ],
            observed_at: now,
            expires_at: now + 30,
            created: Instant::now(),
            cursor: String::new(),
            offset: 0,
        };
        let first = take_page(&mut p).unwrap();
        assert_eq!(first.snapshot.items.len(), 2);
        assert!(context_id(&first.continuation));
        let second = take_page(&mut p).unwrap();
        assert_eq!(second.snapshot.items.len(), 1);
        assert!(second.continuation.is_empty());
        p.expires_at = now;
        assert!(matches!(take_page(&mut p), Err(Status::Expired)));
    }
    #[test]
    fn many_multi_sku_products_continue_at_the_transport_boundary() {
        let now=chrono::Utc::now().timestamp();let mut r=request();r.page_size=100;
        let items=(0..51).flat_map(|id|[item(&format!("P{id:011}/0001")),item(&format!("P{id:011}/0002"))]).collect();
        let mut p=Pending {request:r,items,observed_at:now,expires_at:now+30,created:Instant::now(),cursor:String::new(),offset:0};
        let first=take_page(&mut p).unwrap();assert_eq!(first.snapshot.items.len(),100);assert!(!first.continuation.is_empty());
        let second=take_page(&mut p).unwrap();assert_eq!(second.snapshot.items.len(),2);assert!(second.continuation.is_empty());
    }
    #[test]
    fn request_binding_and_xml_are_strict() {
        let xml = format!(
            "<StoreInventoryRequest><Context>{}</Context><StoreId>GAME1234EFGH</StoreId><TitleId>1</TitleId><MsaAppId>00000000-1111-2222-3333-444444444444</MsaAppId><Market>US</Market><Kinds>2</Kinds><PageSize>1</PageSize></StoreInventoryRequest>",
            "a".repeat(64)
        );
        assert!(parse_request(xml.as_bytes()).is_ok());
        for bad in [
            xml.replace("<Kinds>2", "<Kinds>32"),
            xml.replace("<PageSize>1", "<PageSize>0"),
            xml.replace(
                "</StoreInventoryRequest>",
                "<Context>x</Context></StoreInventoryRequest>",
            ),
            format!("{xml}{xml}"),
        ] {
            assert!(parse_request(bad.as_bytes()).is_err());
        }
        let mut other = request();
        other.context = "b".repeat(64);
        assert!(!same_query(&request(), &other));
    }
}
