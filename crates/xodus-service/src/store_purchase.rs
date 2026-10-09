// SPDX-License-Identifier: GPL-3.0-only
//! One account-bound Microsoft-hosted checkout at a time. No order submission,
//! payment instrument handling, automatic retries, or consumable fulfillment.
use crate::{store_events, store_collections::{auth, model}, store_license::{self, Status}};
use quick_xml::{Reader, events::Event};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{process::Stdio, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, process::{Child, Command}};
use xodus::tokens::TokenManager;

static ACTIVE: AtomicBool = AtomicBool::new(false);
struct Permit;
impl Drop for Permit { fn drop(&mut self) { ACTIVE.store(false, Ordering::Release); } }
#[derive(Clone, Deserialize)]
#[serde(rename = "StorePurchaseRequest", rename_all = "PascalCase", deny_unknown_fields)]
pub struct Request {
    pub context: String, pub operation: String, pub action: String,
    pub store_id: String, pub product_id: String, pub title_id: u32,
    pub msa_app_id: String, pub market: String, pub language: String,
}
fn hex(s: &str, size: usize) -> bool { s.len() == size && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
pub fn parse(input: &[u8]) -> Result<Request, Status> {
    let input = input.strip_suffix(&[0]).unwrap_or(input);
    if input.len() > 2048 || input.contains(&0) { return Err(Status::InvalidRequest); }
    let mut reader = Reader::from_reader(input); let mut depth = 0; let mut roots = 0;
    loop {
        match reader.read_event().map_err(|_| Status::InvalidRequest)? {
            Event::Start(e) => {
                if e.attributes().next().is_some() || depth > 1 { return Err(Status::InvalidRequest); }
                if depth == 0 { if e.name().as_ref() != "StorePurchaseRequest" { return Err(Status::InvalidRequest); } roots += 1; }
                depth += 1;
            }
            Event::End(_) => { if depth == 0 { return Err(Status::InvalidRequest); } depth -= 1; }
            Event::Text(t) if depth == 2 || t.as_ref().chars().all(|c| c.is_ascii_whitespace()) => (),
            Event::Eof => break,
            _ => return Err(Status::InvalidRequest),
        }
    }
    if roots != 1 || depth != 0 { return Err(Status::InvalidRequest); }
    let r: Request = quick_xml::de::from_reader(input).map_err(|_| Status::InvalidRequest)?;
    let product = r.product_id.split('/').collect::<Vec<_>>();
    if !hex(&r.context, 64) || !hex(&r.operation, 32) || !["Start", "Poll", "Cancel"].contains(&r.action.as_str())
        || !model::valid_id(&r.store_id, 12) || !(1..=2).contains(&product.len())
        || !model::valid_id(product[0], 12) || (product.len() == 2 && !model::valid_id(product[1], 4))
        || r.title_id == 0 || !model::valid_app_id(&r.msa_app_id)
        || r.market.len() != 2 || !r.market.bytes().all(|b| b.is_ascii_uppercase())
        || !(2..=35).contains(&r.language.len()) || !r.language.bytes().all(|c| c.is_ascii_alphabetic() || c == b'-') {
        return Err(Status::InvalidRequest);
    }
    Ok(r)
}
pub fn encode(status: &str) -> Vec<u8> {
    // Status is always an internal closed constant, never server text.
    format!("<StorePurchaseResponse><Status>{status}</Status></StorePurchaseResponse>").into_bytes()
}
fn date(v: &Value) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(v.as_str()?).ok().map(|d| d.timestamp())
}
fn offer(catalogue: &Value, r: &Request, now: i64) -> Result<Value, Status> {
    let id = &r.product_id[..12]; let p = &catalogue["Product"];
    if p["ProductId"].as_str() != Some(id) { return Err(Status::Unsupported); }
    let related = p["MarketProperties"].as_array().is_some_and(|markets| markets.iter().any(|m|
        m["RelatedProducts"].as_array().is_some_and(|v| v.iter().any(|v|
            v["RelationshipType"] == "addOnParent" && v["RelatedProductId"] == r.store_id))));
    if id != r.store_id && !related { return Err(Status::Unsupported); }
    // The dialog can purchase the exact offer; subscriptions, bundles and
    // ambiguous SKU selection need their own selection flow first.
    let mut found = Vec::new();
    for entry in p["DisplaySkuAvailabilities"].as_array().ok_or(Status::Unsupported)? {
        let sku = &entry["Sku"]; let properties = &sku["Properties"];
        let sid = sku["SkuId"].as_str().filter(|s| model::valid_id(s, 4)).ok_or(Status::Unsupported)?;
        if r.product_id.len() == 17 && &r.product_id[13..] != sid { continue; }
        if sku["SkuType"] != "full" || properties["IsTrial"] != false || properties["IsPreOrder"] != false || properties["IsBundle"] != false { continue; }
        for a in entry["Availabilities"].as_array().ok_or(Status::Unsupported)? {
            let conditions = &a["Conditions"];
            if !a["Actions"].as_array().is_some_and(|v| v.iter().any(|v| v == "Purchase"))
                || !a["Markets"].as_array().is_some_and(|v| v.iter().any(|v| v == &r.market))
                || !date(&conditions["StartDate"]).is_some_and(|t| t <= now)
                || !date(&conditions["EndDate"]).is_some_and(|t| t > now)
                || !conditions["ClientConditions"]["AllowedPlatforms"].as_array().is_some_and(|v| v.iter().any(|v| v["PlatformName"] == "Windows.Desktop")) { continue; }
            let aid = a["AvailabilityId"].as_str().filter(|s| model::valid_id(s, 12)).ok_or(Status::Unsupported)?;
            found.push(json!({"productId":id,"skuId":sid,"availabilityId":aid}));
        }
    }
    if found.len() != 1 { return Err(Status::Unsupported); }
    Ok(found.remove(0))
}
fn same_checkout(a: &Request, b: &Request) -> bool {
    a.context == b.context && a.operation == b.operation && a.store_id == b.store_id &&
    a.product_id == b.product_id && a.title_id == b.title_id && a.msa_app_id == b.msa_app_id &&
    a.market == b.market && a.language == b.language
}
struct Job { request: Request, child: Child, started: Instant, expires_at: i64, _permit: Permit }
#[derive(Default)]
pub struct Broker { job: Option<Job>, completed: Option<(Request, &'static str)> }
impl Broker {
    pub fn cancel(&mut self) { self.stop("Cancelled"); }
    fn stop(&mut self, status: &'static str) {
        if let Some(mut job) = self.job.take() {
            let _ = job.child.start_kill();
            store_events::emit(if status=="Cancelled" {"cancel"}else{"complete"}, if status=="Cancelled" {"cancelled"}else if status=="Timeout" {"timeout"}else{"failed"});
            self.completed = Some((job.request, status));
        }
    }
    pub async fn handle(&mut self, r: Request, tokens: Arc<TokenManager>) -> Vec<u8> {
        if let Some((completed, status)) = &self.completed {
            if completed.context == r.context && completed.operation == r.operation {
                return encode(if same_checkout(completed, &r) { status } else { "InvalidRequest" });
            }
        }
        if let Some(job) = &self.job {
            if job.request.context != r.context || job.request.operation != r.operation { return encode("Busy"); }
            if !same_checkout(&job.request, &r) { return encode("InvalidRequest"); }
            if r.action == "Cancel" { self.cancel(); return encode("Cancelled"); }
            if job.started.elapsed() > Duration::from_secs(935) || chrono::Utc::now().timestamp() >= job.expires_at + 35 {
                self.stop("Timeout"); return encode("Timeout");
            }
            let job = self.job.as_mut().unwrap();
            match job.child.try_wait() {
                Ok(None) => return encode("Pending"),
                Ok(Some(exit)) if exit.success() => {
                    let mut bytes = Vec::new();
                    let read = match job.child.stdout.take() {
                        Some(out) => tokio::time::timeout(Duration::from_secs(2), out.take(2049).read_to_end(&mut bytes)).await,
                        None => { self.stop("Error"); return encode("Error"); }
                    };
                    let status = if read.is_ok_and(|r| r.is_ok()) && bytes.len() <= 2048 { completion(&bytes) } else { "Error" };
                    self.job.take();
                    self.completed = Some((r, status));
                    store_events::emit("complete", match status {"Succeeded"=>"succeeded", "Cancelled"=>"cancelled", "Expired"=>"expired", "Timeout"=>"timeout", _=>"failed"});
                    return encode(status);
                }
                _ => { self.stop("Error"); return encode("Error"); }
            }
        }
        if r.action != "Start" { return encode("InvalidRequest"); }
        if ACTIVE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return encode("Busy"); }
        let permit = Permit;
        store_events::emit("prepare", "started");
        let prepared = tokio::time::timeout(Duration::from_secs(35), prepare(&r, tokens)).await;
        let mut config = match prepared {
            Ok(Ok(value)) => value,
            Ok(Err(status)) => { store_events::emit("prepare", "failed"); return encode(&format!("{status:?}")); },
            Err(_) => { store_events::emit("prepare", "timeout"); return encode("Timeout"); },
        };
        let Some(helper) = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join("xodus-cli"))) else { return encode("Error"); };
        let mut child = match Command::new(helper).arg("store-purchase")
            .env_remove("XODUS_LOG").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .kill_on_drop(true).spawn() { Ok(c) => c, Err(_) => return encode("Error") };
        store_events::emit("window_open", "started");
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let read = async {
                    let mut lines=BufReader::new(stderr.take(32768)).lines();
                    let mut count=0;
                    while let Ok(Some(line))=lines.next_line().await {
                        if let Some(phase)=store_events::progress(&line) {
                            if count<8 {store_events::emit(phase,match phase {"bootstrap_started"=>"started","load_timeout"|"session_timeout"=>"timeout","expired"=>"expired","bootstrap_error"|"error"=>"failed",_=>"passed"});count+=1;}
                        }
                    }
                };
                let _=tokio::time::timeout(Duration::from_secs(940),read).await;
            });
        }
        let payload = serde_json::to_vec(&config).unwrap();
        config["xToken"] = Value::Null;
        let expires_at = config["expiresAt"].as_i64().unwrap();
        let Some(mut input) = child.stdin.take() else { return encode("Error"); };
        if !tokio::time::timeout(Duration::from_secs(2), input.write_all(&payload)).await.is_ok_and(|r| r.is_ok()) { return encode("Error"); }
        drop(input);
        self.job = Some(Job { request:r, child, started:Instant::now(), expires_at, _permit:permit });
        encode("Pending")
    }
}
fn completion(bytes: &[u8]) -> &'static str {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else { return "Error"; };
    match v["status"].as_str() {
        Some("Succeeded") if v["orderId"].as_str().is_some_and(|s| !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_:".contains(&c))) => "Succeeded",
        Some("Cancelled") => "Cancelled", Some("Expired") => "Expired", Some("Timeout") => "Timeout", _ => "Error",
    }
}
pub(crate) async fn prepare(r: &Request, tokens: Arc<TokenManager>) -> Result<Value, Status> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_| Status::Error)?;
    store_events::emit("catalog", "started");
    let catalog = store_license::fetch_catalogue(&client, &r.product_id[..12], &r.market).await?;
    let mut fields = offer(&catalog, r, chrono::Utc::now().timestamp())?;
    store_events::emit("catalog", "passed");
    store_events::emit("authentication", "started");
    let binding = model::Request {context:r.context.clone(), store_id:r.store_id.clone(), title_id:r.title_id, msa_app_id:r.msa_app_id.clone(), products:vec![]};
    let session = auth::Session::checkout(&binding, &tokens).await?;
    store_events::emit("authentication", "passed");
    fields["xToken"] = json!(session.checkout_token()); fields["expiresAt"] = json!(session.expires_at);
    fields["market"] = json!(r.market); fields["locale"] = json!(r.language);
    Ok(fields)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request { context:"a".repeat(64), operation:"b".repeat(32), action:"Start".into(),
            store_id:"GAME1234EFGH".into(), product_id:"COIN1234EFGH".into(), title_id:1,
            msa_app_id:"0000000012345678".into(), market:"AT".into(), language:"en-US".into() }
    }
    fn catalog() -> Value {
        json!({"Product":{"ProductId":"COIN1234EFGH","MarketProperties":[{"RelatedProducts":[{"RelationshipType":"addOnParent","RelatedProductId":"GAME1234EFGH"}]}],
            "DisplaySkuAvailabilities":[{"Sku":{"SkuId":"0001","SkuType":"full","Properties":{"IsTrial":false,"IsPreOrder":false,"IsBundle":false}},
            "Availabilities":[{"AvailabilityId":"AVAIL1234567","Actions":["Purchase"],"Markets":["AT"],"Conditions":{"StartDate":"2000-01-01T00:00:00Z","EndDate":"2099-01-01T00:00:00Z","ClientConditions":{"AllowedPlatforms":[{"PlatformName":"Windows.Desktop"}]}}}]}]}})
    }
    #[test] fn selects_only_an_exact_unambiguous_live_desktop_offer() {
        let r=request(); let v=catalog();let now=1800000000;
        assert_eq!(offer(&v,&r,now).unwrap()["skuId"],"0001");
        let mut wrong=r.clone();wrong.store_id="OTHR1234EFGH".into();assert!(offer(&v,&wrong,now).is_err());
        wrong=r.clone();wrong.market="DE".into();assert!(offer(&v,&wrong,now).is_err());
        wrong=r.clone();wrong.product_id+="/0002";assert!(offer(&v,&wrong,now).is_err());
        assert!(offer(&v,&r,4102444800).is_err());
        let mut trial=v.clone();trial["Product"]["DisplaySkuAvailabilities"][0]["Sku"]["Properties"]["IsTrial"]=json!(true);assert!(offer(&trial,&r,now).is_err());
        let mut mobile=v.clone();mobile["Product"]["DisplaySkuAvailabilities"][0]["Availabilities"][0]["Conditions"]["ClientConditions"]["AllowedPlatforms"][0]["PlatformName"]=json!("Windows.Mobile");assert!(offer(&mobile,&r,now).is_err());
        let mut ambiguous=v.clone();let a=ambiguous["Product"]["DisplaySkuAvailabilities"][0]["Availabilities"][0].clone();ambiguous["Product"]["DisplaySkuAvailabilities"][0]["Availabilities"].as_array_mut().unwrap().push(a);assert!(offer(&ambiguous,&r,now).is_err());
    }
    #[tokio::test] async fn completed_operation_cannot_start_again_or_change_product() {
        let r=request();let tokens=Arc::new(TokenManager::with_memory());
        let mut broker=Broker {job:None,completed:Some((r.clone(),"Succeeded"))};
        assert_eq!(broker.handle(r.clone(),tokens.clone()).await,encode("Succeeded"));
        let mut other=r.clone();other.product_id="OTHR1234EFGH".into();assert_eq!(broker.handle(other,tokens.clone()).await,encode("InvalidRequest"));
        let mut other=r.clone();other.market="DE".into();assert_eq!(broker.handle(other,tokens.clone()).await,encode("InvalidRequest"));
        let mut unknown=r;unknown.operation="c".repeat(32);unknown.action="Poll".into();assert_eq!(broker.handle(unknown,tokens).await,encode("InvalidRequest"));
    }
    #[tokio::test] async fn forced_timeout_is_not_cached_as_user_cancellation() {
        let r=request();
        let child=Command::new("/bin/true").kill_on_drop(true).spawn().unwrap();
        let mut broker=Broker{job:Some(Job{request:r.clone(),child,started:Instant::now(),expires_at:4102444800,_permit:Permit}),completed:None};
        broker.stop("Timeout");
        assert_eq!(broker.handle(r,Arc::new(TokenManager::with_memory())).await,encode("Timeout"));
    }
    #[test] fn closed_result_protocol() {
        assert_eq!(completion(br#"{"status":"Succeeded"}"#), "Error");
        assert_eq!(completion(br#"{"status":"Succeeded","orderId":"1234-abcd"}"#), "Succeeded");
        assert_eq!(completion(br#"{"status":"Cancelled"}"#), "Cancelled");
        assert_eq!(completion(br#"{"status":"Expired"}"#), "Expired");
        assert_eq!(completion(br#"{"status":"Pending"}"#), "Error");
        assert_eq!(completion(b"not json"), "Error");
    }
    #[test] fn invalid_xml_never_starts_ui() {
        for request in [b"<Other/>".as_slice(), b"<!DOCTYPE x><StorePurchaseRequest/>", b"<StorePurchaseRequest/>\0\0"] { assert!(parse(request).is_err()); }
    }
}
