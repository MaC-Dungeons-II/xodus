//! Narrow consumer-collection evidence. Never infer shared ownership or balances.
use crate::store_license::Status;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq)]
pub struct Wanted {
    pub store_id: String,
    pub kind: u32,
}
#[derive(Clone)]
pub struct Request {
    pub context: String,
    pub store_id: String,
    pub title_id: u32,
    pub msa_app_id: String,
    pub products: Vec<Wanted>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    pub store_id: String,
    pub kind: u32,
    pub acquired_date: i64,
    pub start_date: i64,
    pub end_date: i64,
    pub quantity: u32,
    pub is_trial: bool,
    pub trial_time_remaining_in_seconds: u32,
    pub campaign_id: Option<String>,
    pub developer_offer_id: Option<String>,
}
pub struct Record {
    pub item: Item,
    pub active: bool,
}
pub struct Page {
    pub records: Vec<Record>,
    pub continuation: Option<String>,
}
pub struct Snapshot {
    pub items: Vec<Item>,
    pub absent: Vec<String>,
    pub unknown: Vec<String>,
    pub observed_at: i64,
    pub expires_at: i64,
}

pub fn parent_expiry(records: &[Record], parent: &str, now: i64) -> Result<i64, Status> {
    records
        .iter()
        .filter(|r| {
            r.active
                && r.item.kind == 4
                && r.item.store_id[..12] == *parent
                && r.item.acquired_date <= now
                && r.item.start_date <= now
                && r.item.end_date > now
        })
        .map(|r| r.item.end_date)
        .max()
        .ok_or(Status::Unsupported)
}

/// Each HTTP batch must independently reach a terminal page and carry the
/// positive parent control. An empty later batch cannot borrow earlier proof.
#[derive(Default)]
pub struct BatchPages {
    records: Vec<Record>,
    seen: BTreeSet<String>,
    pages: usize,
    complete: bool,
}
impl BatchPages {
    pub fn push(&mut self, page: Page) -> Result<Option<String>, Status> {
        if self.complete || self.pages >= 20 || self.records.len() + page.records.len() > 1000 {
            return Err(Status::Unsupported);
        }
        self.pages += 1;
        if let Some(cursor) = &page.continuation {
            if !self.seen.insert(cursor.clone()) || self.pages == 20 {
                return Err(Status::Unsupported);
            }
        }
        self.complete = page.continuation.is_none();
        self.records.extend(page.records);
        Ok(page.continuation)
    }
    pub fn finish(self, parent: &str, now: i64) -> Result<(Vec<Record>, i64), Status> {
        if !self.complete {
            return Err(Status::Unsupported);
        }
        let expiry = parent_expiry(&self.records, parent, now)?;
        Ok((self.records, expiry))
    }
}

pub fn valid_id(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
pub fn valid_sku(v: &str) -> bool {
    v.len() == 17 && v.as_bytes()[12] == b'/' && valid_id(&v[..12], 12) && valid_id(&v[13..], 4)
}
pub fn valid_guid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
// MicrosoftGame.config supports both legacy 16-digit hexadecimal MSA IDs
// and newer GUIDs. Preserve the title's exact ID for the token exchange.
pub fn valid_app_id(s: &str) -> bool {
    valid_guid(s) || (s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
pub fn validate(request: &Request) -> Result<(), Status> {
    if request.context.len() != 64
        || !request
            .context
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !valid_id(&request.store_id, 12)
        || request.title_id == 0
        || !valid_app_id(&request.msa_app_id)
        || request.products.is_empty()
        || request.products.len() > 100
    {
        return Err(Status::InvalidRequest);
    }
    let mut seen = BTreeSet::new();
    for p in &request.products {
        if !valid_sku(&p.store_id)
            || ![1, 2, 4, 8, 16].contains(&p.kind)
            || !seen.insert(&p.store_id)
        {
            return Err(Status::InvalidRequest);
        }
    }
    Ok(())
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Status> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(Status::Unsupported)
}
fn date(v: &Value, key: &str) -> Result<i64, Status> {
    chrono::DateTime::parse_from_rfc3339(text(v, key)?)
        .map(|d| d.timestamp())
        .map_err(|_| Status::Unsupported)
}
fn optional(v: &Value, key: &str) -> Result<Option<String>, Status> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= 512 && s.chars().all(|c| !c.is_control()) => {
            Ok(Some(s.clone()))
        }
        _ => Err(Status::Unsupported),
    }
}
fn duration(s: &str) -> Result<u32, Status> {
    let parts = s.split(':').collect::<Vec<_>>();
    if !(3..=4).contains(&parts.len()) {
        return Err(Status::Unsupported);
    }
    let number = |s: &str| -> Result<u64, Status> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Status::Unsupported);
        }
        s.parse().map_err(|_| Status::Unsupported)
    };
    let (days, hours) = if parts.len() == 4 {
        (number(parts[0])?, number(parts[1])?)
    } else if let Some((d, h)) = parts[0].split_once('.') {
        (number(d)?, number(h)?)
    } else {
        (0, number(parts[0])?)
    };
    let minutes = number(parts[parts.len() - 2])?;
    let last = parts[parts.len() - 1];
    let seconds = if let Some((s, f)) = last.split_once('.') {
        if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Status::Unsupported);
        }
        number(s)?
    } else {
        number(last)?
    };
    if hours > 23 || minutes > 59 || seconds > 59 {
        return Err(Status::Unsupported);
    }
    days.checked_mul(86400)
        .and_then(|d| d.checked_add(hours * 3600 + minutes * 60 + seconds))
        .and_then(|s| u32::try_from(s).ok())
        .ok_or(Status::Unsupported)
}
pub fn parse_page(value: &Value) -> Result<Page, Status> {
    let rows = value
        .get("items")
        .and_then(Value::as_array)
        .ok_or(Status::Unsupported)?;
    if rows.len() > 100 {
        return Err(Status::Unsupported);
    }
    let continuation = match value.get("continuationToken") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) if s.len() <= 8192 => Some(s.clone()),
        _ => return Err(Status::Unsupported),
    };
    let mut records = Vec::new();
    for row in rows {
        let product = text(row, "productId")?;
        let sku = text(row, "skuId")?;
        if !valid_id(product, 12) || !valid_id(sku, 4) {
            return Err(Status::Unsupported);
        }
        let kind_name = text(row, "productKind")?;
        if let Some(alias) = row.get("productType") {
            if alias.as_str() != Some(kind_name) {
                return Err(Status::Unsupported);
            }
        }
        let kind = match kind_name {
            "Consumable" => 1,
            "Durable" => 2,
            "Game" => 4,
            "Pass" => 8,
            "UnmanagedConsumable" => 16,
            _ => return Err(Status::Unsupported),
        };
        let status = text(row, "status")?;
        if !["Active", "Expired", "Revoked", "Banned", "Suspended"].contains(&status) {
            return Err(Status::Unsupported);
        }
        if text(row, "sharingSource")? != "None" {
            return Err(Status::Unsupported);
        }
        let satisfying = row
            .get("satisfiedByProductIds")
            .and_then(Value::as_array)
            .ok_or(Status::Unsupported)?;
        if satisfying.len() > 1000
            || satisfying
                .iter()
                .any(|v| !v.as_str().is_some_and(|s| valid_id(s, 12)))
        {
            return Err(Status::Unsupported);
        }
        let acquired_date = date(row, "acquiredDate")?;
        let start_date = date(row, "startDate")?;
        let end_date = date(row, "endDate")?;
        if start_date >= end_date {
            return Err(Status::Unsupported);
        }
        // Collections v8 documents quantity as optional and non-consumable
        // quantity as exactly one. Expanded satisfying Game records omit it in
        // genuine responses. Consumable balances always require the field.
        let quantity = match row.get("quantity") {
            None if matches!(kind, 2 | 4 | 8) => 1,
            Some(value) => value
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(Status::Unsupported)?,
            _ => return Err(Status::Unsupported),
        };
        if matches!(kind, 2 | 4 | 8) && quantity != 1 {
            return Err(Status::Unsupported);
        }
        let trial = row
            .get("trialData")
            .and_then(Value::as_object)
            .ok_or(Status::Unsupported)?;
        let is_trial = trial
            .get("isTrial")
            .and_then(Value::as_bool)
            .ok_or(Status::Unsupported)?;
        let in_trial = trial
            .get("isInTrialPeriod")
            .and_then(Value::as_bool)
            .ok_or(Status::Unsupported)?;
        if in_trial && !is_trial {
            return Err(Status::Unsupported);
        }
        let trial_time_remaining_in_seconds = match trial.get("trialTimeRemaining") {
            Some(Value::String(s)) => duration(s)?,
            None | Some(Value::Null) if !is_trial && !in_trial => 0,
            _ => return Err(Status::Unsupported),
        };
        records.push(Record {
            item: Item {
                store_id: format!("{product}/{sku}"),
                kind,
                acquired_date,
                start_date,
                end_date,
                quantity,
                is_trial,
                trial_time_remaining_in_seconds,
                campaign_id: optional(row, "campaignId")?,
                developer_offer_id: optional(row, "devOfferId")?,
            },
            active: status == "Active",
        });
    }
    Ok(Page {
        records,
        continuation,
    })
}

/// Only after every requested server page was acquired, and an active known
/// parent proved this account/title response. Missing shareable SKUs stay unknown.
pub fn finish(
    request: &Request,
    records: Vec<Record>,
    now: i64,
    expires: i64,
) -> Result<Snapshot, Status> {
    validate(request)?;
    if expires <= now {
        return Err(Status::Expired);
    }
    let parent_expires = parent_expiry(&records, &request.store_id, now)?;
    let mut active = BTreeMap::<String, Item>::new();
    for row in records {
        if row.item.acquired_date > now {
            return Err(Status::Unsupported);
        }
        if !row.active || row.item.start_date > now || row.item.end_date <= now {
            continue;
        }
        if let Some(wanted) = request
            .products
            .iter()
            .find(|p| p.store_id == row.item.store_id)
        {
            if wanted.kind != row.item.kind {
                return Err(Status::Unsupported);
            }
            if let Some(previous) = active.get(&row.item.store_id) {
                if previous != &row.item {
                    return Err(Status::Unsupported);
                }
            } else {
                active.insert(row.item.store_id.clone(), row.item);
            }
        }
    }
    let mut items = Vec::new();
    let mut absent = Vec::new();
    let mut unknown = Vec::new();
    let mut expires_at = expires.min(parent_expires).min(now.saturating_add(30));
    for wanted in &request.products {
        if let Some(item) = active.remove(&wanted.store_id) {
            expires_at = expires_at.min(item.end_date);
            items.push(item);
        } else if matches!(wanted.kind, 1 | 16) {
            absent.push(wanted.store_id.clone());
        } else {
            unknown.push(wanted.store_id.clone());
        }
    }
    Ok(Snapshot {
        items,
        absent,
        unknown,
        observed_at: now,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn both_microsoft_application_id_formats_are_supported() {
        assert!(valid_app_id("000000001234ABCD"));
        assert!(valid_app_id("00000000-1111-2222-3333-444444444444"));
        for bad in ["", "000000001234ABCD&", "000000001234ABCG", "123", "{00000000-1111-2222-3333-444444444444}"] {
            assert!(!valid_app_id(bad));
        }
        let mut r=request();r.msa_app_id="000000001234ABCD".into();assert!(validate(&r).is_ok());
    }
    fn request() -> Request {
        Request {
            context: "a".repeat(64),
            store_id: "ABCD1234EFGH".into(),
            title_id: 123,
            msa_app_id: "00000000-1111-2222-3333-444444444444".into(),
            products: vec![
                Wanted {
                    store_id: "COIN1234EFGH/0001".into(),
                    kind: 16,
                },
                Wanted {
                    store_id: "GAME1234EFGH/0001".into(),
                    kind: 4,
                },
            ],
        }
    }
    fn row() -> Value {
        json!({"productId":"ABCD1234EFGH","skuId":"0001","productKind":"Game","status":"Active","acquiredDate":"2020-01-01T00:00:00.1234567Z","startDate":"2020-01-01T00:00:00Z","endDate":"9999-12-31T23:59:59.9999999+00:00","quantity":1,"trialData":{"isTrial":false,"isInTrialPeriod":false},"sharingSource":"None","satisfiedByProductIds":[]})
    }
    #[test]
    fn actual_shape_and_far_future_dates() {
        let page = parse_page(&json!({"items":[row()]})).unwrap();
        assert_eq!(page.records[0].item.end_date, 253402300799);
        assert_eq!(page.records[0].item.trial_time_remaining_in_seconds, 0);
        assert!(page.records[0].item.campaign_id.is_none());
    }
    #[test]
    fn expanded_nonconsumable_quantity_is_documented_one_only() {
        for kind in ["Game", "Durable", "Pass"] {
            let mut record = row();
            record["productKind"] = json!(kind);
            record.as_object_mut().unwrap().remove("quantity");
            assert_eq!(
                parse_page(&json!({"items":[record.clone()]}))
                    .unwrap()
                    .records[0]
                    .item
                    .quantity,
                1
            );
            record["quantity"] = json!(0);
            assert!(parse_page(&json!({"items":[record]})).is_err());
        }
        for kind in ["Consumable", "UnmanagedConsumable"] {
            let mut record = row();
            record["productKind"] = json!(kind);
            record.as_object_mut().unwrap().remove("quantity");
            assert!(parse_page(&json!({"items":[record.clone()]})).is_err());
            record["quantity"] = json!(0);
            assert_eq!(
                parse_page(&json!({"items":[record]})).unwrap().records[0]
                    .item
                    .quantity,
                0
            );
        }
    }
    #[test]
    fn narrow_negative_scope_and_parent_control() {
        let rows = parse_page(&json!({"items":[row()]})).unwrap().records;
        let s = finish(&request(), rows, 1800000000, 1900000000).unwrap();
        assert_eq!(s.absent, ["COIN1234EFGH/0001"]);
        assert_eq!(s.unknown, ["GAME1234EFGH/0001"]);
        assert!(matches!(
            finish(&request(), vec![], 1800000000, 1900000000),
            Err(Status::Unsupported)
        ));
    }
    #[test]
    fn positive_exact_sku_and_active_time() {
        let mut coin = row();
        coin["productId"] = json!("COIN1234EFGH");
        coin["productKind"] = json!("UnmanagedConsumable");
        let s = finish(
            &request(),
            parse_page(&json!({"items":[row(),coin.clone()]}))
                .unwrap()
                .records,
            1800000000,
            1900000000,
        )
        .unwrap();
        assert_eq!(s.items.len(), 1);
        assert!(s.absent.is_empty());
        coin["status"] = json!("Expired");
        let s = finish(
            &request(),
            parse_page(&json!({"items":[row(),coin]})).unwrap().records,
            1800000000,
            1900000000,
        )
        .unwrap();
        assert_eq!(s.absent.len(), 1);
    }
    #[test]
    fn contradictory_active_duplicates_fail() {
        let mut coin = row();
        coin["productId"] = json!("COIN1234EFGH");
        coin["productKind"] = json!("UnmanagedConsumable");
        let mut changed = coin.clone();
        changed["quantity"] = json!(2);
        assert!(matches!(
            finish(
                &request(),
                parse_page(&json!({"items":[row(),coin,changed]}))
                    .unwrap()
                    .records,
                1800000000,
                1900000000
            ),
            Err(Status::Unsupported)
        ));
    }
    #[test]
    fn malformed_and_unproven_fields_fail() {
        for (field, value) in [
            ("quantity", json!(-1)),
            ("quantity", json!(4294967296u64)),
            ("quantity", json!(1.5)),
            ("startDate", json!("invalid")),
            ("status", json!("Unknown")),
            ("sharingSource", json!("Shared")),
            ("productType", json!("Durable")),
            ("skuId", json!("abc")),
            ("trialData", json!({"isTrial":true,"isInTrialPeriod":true})),
            ("satisfiedByProductIds", json!(["../bad"])),
        ] {
            let mut r = row();
            r[field] = value;
            assert!(parse_page(&json!({"items":[r]})).is_err(), "{field}");
        }
    }
    #[test]
    fn trial_duration_checked() {
        for (s, n) in [
            ("09:43:52.8580690", 35032),
            ("1.09:43:52", 121432),
            ("01:09:43:52.000", 121432),
            ("00:00:00", 0),
        ] {
            assert_eq!(duration(s).unwrap(), n);
        }
        for s in [
            "24:00:00",
            "00:60:00",
            "00:00:60",
            "-1:00:00",
            "99999999999999:00:00:00",
            "00:00:00.bad",
        ] {
            assert!(duration(s).is_err());
        }
    }
    #[test]
    fn page_contract_never_infers_missing_items_empty() {
        assert!(parse_page(&json!({})).is_err());
        assert!(parse_page(&json!({"items":[],"continuationToken":13})).is_err());
        assert!(
            parse_page(&json!({"items":[],"continuationToken":"opaque"}))
                .unwrap()
                .continuation
                .is_some()
        );
    }
    #[test]
    fn empty_intermediate_page_requires_terminal_parent() {
        let mut b = BatchPages::default();
        assert_eq!(
            b.push(parse_page(&json!({"items":[],"continuationToken":"opaque"})).unwrap())
                .unwrap(),
            Some("opaque".into())
        );
        assert!(
            b.push(parse_page(&json!({"items":[row()]})).unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(b.finish("ABCD1234EFGH", 1800000000).unwrap().0.len(), 1);
        let mut empty = BatchPages::default();
        empty
            .push(parse_page(&json!({"items":[]})).unwrap())
            .unwrap();
        assert!(empty.finish("ABCD1234EFGH", 1800000000).is_err());
    }
    #[test]
    fn repeated_or_unfinished_paging_never_publishes() {
        let mut b = BatchPages::default();
        b.push(parse_page(&json!({"items":[row()],"continuationToken":"same"})).unwrap())
            .unwrap();
        assert!(b.finish("ABCD1234EFGH", 1800000000).is_err());
        let mut b = BatchPages::default();
        b.push(parse_page(&json!({"items":[row()],"continuationToken":"same"})).unwrap())
            .unwrap();
        assert!(
            b.push(parse_page(&json!({"items":[],"continuationToken":"same"})).unwrap())
                .is_err()
        );
        let mut b = BatchPages::default();
        for i in 0..19 {
            b.push(parse_page(&json!({"items":[],"continuationToken":i.to_string()})).unwrap())
                .unwrap();
        }
        assert!(
            b.push(parse_page(&json!({"items":[row()],"continuationToken":"last"})).unwrap())
                .is_err()
        );
    }
    #[test]
    fn independent_batches_cannot_borrow_parent() {
        let mut good = BatchPages::default();
        good.push(parse_page(&json!({"items":[row()]})).unwrap())
            .unwrap();
        assert!(good.finish("ABCD1234EFGH", 1800000000).is_ok());
        let mut other = BatchPages::default();
        other
            .push(parse_page(&json!({"items":[]})).unwrap())
            .unwrap();
        assert!(other.finish("ABCD1234EFGH", 1800000000).is_err());
    }
    #[test]
    fn parent_expiry_bounds_all_negative_evidence() {
        let mut rows = parse_page(&json!({"items":[row()]})).unwrap().records;
        rows[0].item.end_date = 1800000003;
        let s = finish(&request(), rows, 1800000000, 1900000000).unwrap();
        assert_eq!(s.expires_at, 1800000003);
    }
    #[test]
    fn contradictory_trial_and_future_acquisition_fail() {
        let mut r = row();
        r["trialData"] =
            json!({"isTrial":false,"isInTrialPeriod":true,"trialTimeRemaining":"00:00:00"});
        assert!(parse_page(&json!({"items":[r]})).is_err());
        let mut rows = parse_page(&json!({"items":[row()]})).unwrap().records;
        rows[0].item.acquired_date = 1800000001;
        assert!(parent_expiry(&rows, "ABCD1234EFGH", 1800000000).is_err());
        assert!(finish(&request(), rows, 1800000000, 1900000000).is_err());
    }
}
