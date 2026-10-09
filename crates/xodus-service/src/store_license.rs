//! Genuine PC full-game licenses from Microsoft-signed v8 tokens. No inventory,
//! trial emulation, offline fallback, token refresh writes or purchase operations.
#[path="store_license/verified_token.rs"]pub(crate) mod verified_token;

use base64::prelude::*;
use quick_xml::{Reader,events::Event};
use serde::{Deserialize,Serialize};
use serde_json::Value;
use sha2::{Digest,Sha256};
use std::{sync::Arc,time::{Duration,Instant}};
use xodus::{models::{live::ExchangeUserTokenOutcome,secrets::{LegacyToken,Token},soap},tokens::TokenManager};

#[derive(Clone,Deserialize)]
#[serde(rename="StoreGameLicenseRequest",rename_all="PascalCase",deny_unknown_fields)]
pub struct Request {
    pub context:String,pub store_id:String,pub package_family_name:String,pub market:String,
    #[serde(default)] pub durable_store_id:Option<String>,
}

#[derive(Clone,Copy,Serialize,Debug,PartialEq,Eq)]
pub enum Status {Unavailable,Expired,NotLicensed,Unsupported,InvalidRequest,Error,Timeout}

impl From<xodus::api::live::RSTError> for Status {
    fn from(error:xodus::api::live::RSTError)->Self {
        use xodus::tokens::session::SessionError;
        match SessionError::from(error) {
            SessionError::SignInRequired=>Self::Expired,
            SessionError::Timeout=>Self::Timeout,
            _=>Self::Error,
        }
    }
}

#[derive(Clone,Serialize)]
#[serde(rename_all="PascalCase")]
pub struct GameLicense {
    pub sku_store_id:String,
    pub is_active:bool,
    pub is_trial_owned_by_this_user:bool,
    pub is_disc_license:bool,
    pub is_trial:bool,
    pub trial_time_remaining_in_seconds:u32,
    pub trial_unique_id:String,
    pub expiration_date:i64,
    pub revision:String,
}

struct Observation {
    license:GameLicense,
    // Retained verified candidates are evidence for these explicit products,
    // never a claim that the title's full entitlement inventory was enumerated.
    _candidates:Vec<verified_token::Product>,
    jwt_expires_at:i64,
    observed_at:i64,
    observed_instant:Instant,
}
struct Cached {key:(String,String,String,String),observation:Observation}
#[derive(Default)]
pub struct LicenseCache {cached:Option<Cached>}

pub fn parse_request(input:&[u8])->Result<Request,Status> {
    let input=input.strip_suffix(&[0]).unwrap_or(input);
    if input.is_empty() || input.len()>1024 || input.contains(&0) {return Err(Status::InvalidRequest);}
    let mut reader=Reader::from_reader(input);let mut depth=0;let mut roots=0;
    loop {
        match reader.read_event().map_err(|_|Status::InvalidRequest)? {
            Event::Start(e)=>{
                if e.attributes().next().is_some() || depth>1 {return Err(Status::InvalidRequest);}
                if depth==0 {if e.name().as_ref()!="StoreGameLicenseRequest" {return Err(Status::InvalidRequest);}roots+=1;}
                else if !["Context","StoreId","PackageFamilyName","Market","DurableStoreId"].contains(&e.name().as_ref()) {return Err(Status::InvalidRequest);}
                depth+=1;
            },
            Event::End(_)=>{if depth==0{return Err(Status::InvalidRequest);}depth-=1;},
            Event::Text(t)=>{if depth!=2 && !t.as_ref().chars().all(|c|c.is_ascii_whitespace()){return Err(Status::InvalidRequest);}},
            Event::Decl(_) if roots==0=>(),
            Event::Eof=>break,
            _=>return Err(Status::InvalidRequest),
        }
    }
    if roots!=1 || depth!=0 {return Err(Status::InvalidRequest);}
    let request:Request=quick_xml::de::from_reader(input).map_err(|_|Status::InvalidRequest)?;
    if request.context.len()!=64 || !request.context.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
        || request.store_id.len()!=12 || !request.store_id.bytes().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit())
        || request.market.len()!=2 || !request.market.bytes().all(|b|b.is_ascii_uppercase())
        || request.package_family_name.is_empty() || request.package_family_name.len()>255
        || !request.package_family_name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'.'||b==b'-')
        || request.durable_store_id.as_ref().is_some_and(|id| id==&request.store_id || id.len()!=12 || !id.bytes().all(|b| b.is_ascii_uppercase()||b.is_ascii_digit())) {return Err(Status::InvalidRequest);}
    Ok(request)
}

pub fn encode(result:Result<GameLicense,Status>)->Vec<u8> {
    // Serialize the closed field set explicitly: quick_xml flatten is not used.
    let content=match result {
        Ok(license)=>{
            let inner=quick_xml::se::to_string(&license).expect("fixed license serialization");
            format!("<Status>Available</Status>{}",inner.strip_prefix("<GameLicense>").unwrap().strip_suffix("</GameLicense>").unwrap())
        },
        Err(status)=>format!("<Status>{status:?}</Status>"),
    };
    format!("<StoreGameLicenseResponse>{content}</StoreGameLicenseResponse>").into_bytes()
}

impl LicenseCache {
    pub fn clear(&mut self){self.cached=None;}
    pub async fn query(&mut self,request:&Request,tokens:Arc<TokenManager>)->Result<GameLicense,Status> {
        let key=(request.context.clone(),request.store_id.clone(),request.package_family_name.clone(),request.market.clone());
        let now=chrono::Utc::now().timestamp();
        if let Some(c)=self.cached.as_ref().filter(|_|request.durable_store_id.is_none()) {
            if c.key==key && c.observation.observed_instant.elapsed()<Duration::from_secs(60)
                && now>=c.observation.observed_at && now<c.observation.jwt_expires_at
                && now<c.observation.license.expiration_date {return Ok(c.observation.license.clone());}
        }
        self.cached=None;
        let cacheable=request.durable_store_id.is_none();
        let request=request.clone();
        // Existing token helpers may panic on an unsupported server response;
        // isolate that as failure and keep the request/connection state alive.
        let mut worker=tokio::task::JoinSet::new();
        worker.spawn(async move {observe(&request,&tokens).await});
        let observed=match tokio::time::timeout(Duration::from_secs(35),worker.join_next()).await {
            Ok(Some(Ok(result)))=>result?,
            Ok(_)=>return Err(Status::Error),
            Err(_)=>{worker.abort_all();while worker.join_next().await.is_some() {}return Err(Status::Timeout);},
        };
        let out=observed.license.clone();
        if cacheable {self.cached=Some(Cached{key,observation:observed});}
        Ok(out)
    }
}

fn valid_device(device:&LegacyToken)->bool {
    device.binary_secret.as_ref().and_then(|s|BASE64_STANDARD.decode(s).ok()).is_some_and(|v|v.len()==4096)
        && quick_xml::de::from_str::<soap::EncryptedData>(&device.token).is_ok()
}

pub(crate) async fn acquire_msa_tokens(client:&reqwest::Client,tokens:&TokenManager)->Result<(String,String,String),Status> {
    let Token::Legacy(device)=tokens.get_device_sts_token().map_err(|_|Status::Unavailable)? else{return Err(Status::Unavailable);};
    let Token::Legacy(user)=tokens.get_user_sts_token().map_err(|_|Status::Unavailable)? else{return Err(Status::Unavailable);};
    if !valid_device(&device) || quick_xml::de::from_str::<soap::EncryptedData>(&user.token).is_err(){return Err(Status::Unavailable);}
    let info=tokens.get_user().map_err(|_|Status::Unavailable)?;
    if info.puid.is_empty() || info.username.is_empty(){return Err(Status::Unavailable);}
    const APP:&str="{d6d5a677-0872-4ab0-9442-bb792fce85c5}";
    let device_ms=xodus::api::live::exchange_device_token(client,device.clone(),APP.into(),"www.microsoft.com".into(),Some(soap::PolicyReference::mbi_ssl())).await.map_err(|_|Status::Error)?;
    let user_result=xodus::api::live::exchange_user_token(client,user,info.username,device,None,Some("Silent".into()),APP.into(),&[("www.microsoft.com".into(),Some(soap::PolicyReference::mbi_ssl()))]).await.map_err(Status::from)?;
    let user_ms=match user_result {
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponseCollection(mut c)) if c.security_tokens.len()==1=>c.security_tokens.remove(0),
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(r))=>*r,
        ExchangeUserTokenOutcome::Fault(pp) => return Err(match xodus::tokens::session::fault(pp.as_ref()) {
            xodus::tokens::session::SessionError::SignInRequired => Status::Expired, _ => Status::Error,
        }),
        _=>return Err(Status::Error),
    };
    let Token::Compact(device_ms)=Token::from(device_ms) else{return Err(Status::Unsupported);};
    let Token::Compact(user_ms)=Token::from(user_ms) else{return Err(Status::Unsupported);};
    Ok((device_ms,user_ms,info.puid))
}

async fn observe(request:&Request,tokens:&TokenManager)->Result<Observation,Status> {
    let client=reqwest::Client::builder().timeout(Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_|Status::Error)?;
    let (device_ms,user_ms,puid)=acquire_msa_tokens(&client,tokens).await?;
    let nonce=verified_token::nonce().map_err(|_|Status::Error)?;
    let product=request.durable_store_id.as_ref().unwrap_or(&request.store_id);
    let token=xodus::licensing::content::get_license_token(&client,device_ms,user_ms,puid,request.store_id.clone(),vec![product.clone()],nonce.clone()).await.map_err(|_|Status::Error)?;
    let verified=verified_token::verify(&client,&token,&nonce).await.map_err(|stage|{tracing::warn!(stage,"Store license verification failed");Status::Error})?;
    let catalogue=fetch_catalogue(&client,product,&request.market).await?;
    let now=chrono::Utc::now().timestamp();
    let license=map_verified_license(&verified,&catalogue,request,now)?;
    Ok(Observation{license,_candidates:verified.products,jwt_expires_at:verified.expires_at,observed_at:now,observed_instant:Instant::now()})
}

fn map_verified_license(verified:&verified_token::VerifiedToken,catalogue:&Value,request:&Request,now:i64)->Result<GameLicense,Status> {
    // Catalogue I/O can outlive a short token or overlap a clock adjustment.
    // Check the signed validity interval again before publishing any result.
    if now>=verified.expires_at || now<verified.not_before {return Err(Status::Expired);}
    if request.durable_store_id.is_some() {return map_durable_license(verified,catalogue,request,now);}
    map_full_license(&verified.products,catalogue,request,now)
}

fn map_durable_license(verified:&verified_token::VerifiedToken,catalogue:&Value,request:&Request,now:i64)->Result<GameLicense,Status> {
    let target=request.durable_store_id.as_ref().ok_or(Status::InvalidRequest)?;
    let p=&catalogue["Product"];
    if p["ProductId"].as_str()!=Some(target) || p["ProductKind"].as_str()!=Some("Durable") {return Err(Status::Unsupported);}
    let markets=p["MarketProperties"].as_array().ok_or(Status::Unsupported)?;
    if !markets.iter().any(|m|m["RelatedProducts"].as_array().is_some_and(|r|r.iter().any(|r|
        r["RelationshipType"].as_str()==Some("addOnParent") && r["RelatedProductId"].as_str()==Some(&request.store_id)))) {return Err(Status::Unsupported);}
    if verified.products.iter().any(|p|p.product_id!=*target && p.product_id!=request.store_id) {return Err(Status::Error);}
    let skus=p["DisplaySkuAvailabilities"].as_array().ok_or(Status::Unsupported)?;
    let mut candidates=Vec::new();
    for grant in verified.products.iter().filter(|p|p.product_id==*target && p.ends_at>now) {
        let matching=skus.iter().filter(|s|s["Sku"]["SkuId"].as_str()==Some(&grant.sku_id)).collect::<Vec<_>>();
        if matching.len()!=1 {return Err(Status::Unsupported);}
        let sku=&matching[0]["Sku"];let props=&sku["Properties"];
        if sku["SkuType"].as_str()!=Some("full") || props["IsTrial"].as_bool()!=Some(false)
            || props["IsPreOrder"].as_bool()!=Some(false) || props["IsBundle"].as_bool()!=Some(false) {return Err(Status::Unsupported);}
        candidates.push(grant);
    }
    candidates.sort_by(|a,b|b.ends_at.cmp(&a.ends_at).then_with(||a.sku_id.cmp(&b.sku_id)));
    // Absence is not a claim about device-shared rights. No usable online
    // license is returned unless Microsoft signed a current exact grant.
    let selected=candidates.first().ok_or(Status::Unavailable)?;
    let sku_store_id=format!("{}/{}",selected.product_id,selected.sku_id);
    // A native handle must renew this online observation. It is never an
    // offline license and cannot outlive the signed JWT or product grant.
    let expiration_date=selected.ends_at.min(verified.expires_at).min(now+60);
    let revision=Sha256::digest(format!("xodus-durable-digital-v1\0{sku_store_id}\0{expiration_date}").as_bytes()).iter().map(|b|format!("{b:02x}")).collect();
    Ok(GameLicense{sku_store_id,is_active:true,is_trial_owned_by_this_user:false,is_disc_license:false,is_trial:false,trial_time_remaining_in_seconds:0,trial_unique_id:String::new(),expiration_date,revision})
}

pub(crate) async fn fetch_catalogue(client:&reqwest::Client,product:&str,market:&str)->Result<Value,Status> {
    let response=client.get(format!("https://displaycatalog.mp.microsoft.com/v7.0/products/{product}?market={market}&languages=en-US")).send().await.map_err(|_|Status::Error)?;
    if std::env::var_os("XODUS_COLLECTIONS_DIAGNOSTICS").is_some() {
        eprintln!("[collections-broker] stage=catalog http={}",response.status().as_u16());
    }
    let mut response=response.error_for_status().map_err(|_|Status::Error)?;
    let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await.map_err(|_|Status::Error)? {if bytes.len()+chunk.len()>4*1024*1024{return Err(Status::Error);}bytes.extend_from_slice(&chunk);}
    serde_json::from_slice(&bytes).map_err(|_|Status::Error)
}

fn map_full_license(products:&[verified_token::Product],catalogue:&Value,request:&Request,now:i64)->Result<GameLicense,Status> {
    let product=&catalogue["Product"];
    if product["ProductId"].as_str()!=Some(&request.store_id){return Err(Status::Error);}
    let skus=product["DisplaySkuAvailabilities"].as_array().ok_or(Status::Error)?;
    let mut candidates=Vec::new();let mut entitled=false;let mut unexpired=false;
    for licensed in products.iter().filter(|p|p.product_id==request.store_id) {
        entitled=true;
        if licensed.ends_at<=now {continue;}
        unexpired=true;
        let matches:Vec<_>=skus.iter().filter(|s|s["Sku"]["SkuId"].as_str()==Some(licensed.sku_id.as_str())).collect();
        if matches.len()!=1 {return Err(Status::Unsupported);}
        let sku=&matches[0]["Sku"];let properties=&sku["Properties"];
        if sku["SkuType"].as_str()!=Some("full") || properties["IsTrial"].as_bool()!=Some(false)
            || properties["IsPreOrder"].as_bool()!=Some(false) || properties["IsBundle"].as_bool()!=Some(false)
            || properties["FulfillmentType"].as_str()!=Some("MSIXVC") {continue;}
        let Some(packages)=properties["Packages"].as_array() else{continue;};
        let content_ids:std::collections::BTreeSet<_>=packages.iter().filter(|p|
            p["PackageFamilyName"].as_str()==Some(request.package_family_name.as_str()) && p["PackageFormat"].as_str()==Some("MSIXVC")
            && p["PlatformDependencies"].as_array().is_some_and(|v|v.iter().any(|v|v["PlatformName"].as_str()==Some("Windows.Desktop"))))
            .filter_map(|p|p["ContentId"].as_str()).collect();
        if content_ids.len()!=1 || content_ids.iter().any(|v|v.len()!=36 || !v.bytes().all(|b|b.is_ascii_hexdigit()||b==b'-')) {continue;}
        candidates.push(licensed);
    }
    if !entitled{return Err(Status::NotLicensed);}
    candidates.sort_by(|a,b|b.ends_at.cmp(&a.ends_at).then_with(||a.sku_id.cmp(&b.sku_id)));
    let selected=candidates.first().ok_or(if unexpired{Status::Unsupported}else{Status::Expired})?;
    let sku_store_id=format!("{}/{}",selected.product_id,selected.sku_id);
    let revision=Sha256::digest(format!("xodus-full-digital-v1\0{sku_store_id}\0{}",selected.ends_at).as_bytes()).iter().map(|b|format!("{b:02x}")).collect();
    Ok(GameLicense{sku_store_id,is_active:true,is_trial_owned_by_this_user:false,is_disc_license:false,is_trial:false,trial_time_remaining_in_seconds:0,trial_unique_id:String::new(),expiration_date:selected.ends_at,revision})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn request()->Request {Request{context:"a".repeat(64),store_id:"ABCD1234EFGH".into(),package_family_name:"Test.Game_publisher".into(),market:"AT".into(),durable_store_id:None}}
    fn catalogue()->Value {
        let sku=|id|json!({"Sku":{"SkuId":id,"SkuType":"full","Properties":{"IsTrial":false,"IsPreOrder":false,"IsBundle":false,"FulfillmentType":"MSIXVC","Packages":[{"PackageFamilyName":"Test.Game_publisher","PackageFormat":"MSIXVC","ContentId":"12345678-1234-1234-1234-123456789abc","PlatformDependencies":[{"PlatformName":"Windows.Desktop"}]}]}}});
        json!({"Product":{"ProductId":"ABCD1234EFGH","DisplaySkuAvailabilities":[sku("0001"),sku("0002")]}})
    }
    fn product(sku:&str,end:i64)->verified_token::Product {verified_token::Product{product_id:request().store_id,sku_id:sku.into(),ends_at:end}}
    #[test]
    fn strict_request_and_status_shapes() {
        let xml=format!("<StoreGameLicenseRequest><Context>{}</Context><StoreId>ABCD1234EFGH</StoreId><PackageFamilyName>Test.Game_publisher</PackageFamilyName><Market>AT</Market></StoreGameLicenseRequest>","a".repeat(64));
        assert!(parse_request(xml.as_bytes()).is_ok());assert!(parse_request(format!("{xml}\0").as_bytes()).is_ok());
        for bad in [xml.replace("<Market>AT</Market>","<Market>AT</Market><Market>US</Market>"),xml.replace("<Market>AT</Market>","<Market>../</Market>"),format!("<!DOCTYPE x>{xml}"),format!("{xml}{xml}"),format!("{xml}\0\0"),xml.replace("<Context>","<Context attr='x'>"),xml.replace("ABCD1234EFGH","../evil/path")]
            {assert!(parse_request(bad.as_bytes()).is_err());}
        for status in [Status::Unavailable,Status::Expired,Status::NotLicensed,Status::Unsupported,Status::InvalidRequest,Status::Error,Status::Timeout] {
            let encoded=String::from_utf8(encode(Err(status))).unwrap();
            assert_eq!(encoded,format!("<StoreGameLicenseResponse><Status>{status:?}</Status></StoreGameLicenseResponse>"));
        }
    }
    #[test]
    fn verified_full_candidates_select_latest_then_stable_sku() {
        let a=map_full_license(&[product("0001",100),product("0002",200)],&catalogue(),&request(),1).unwrap();
        assert_eq!(a.sku_store_id,"ABCD1234EFGH/0002");assert_eq!(a.expiration_date,200);
        assert!(a.is_active);assert!(!a.is_trial&&!a.is_trial_owned_by_this_user&&!a.is_disc_license);assert_eq!(a.trial_time_remaining_in_seconds,0);assert!(a.trial_unique_id.is_empty());
        let b=map_full_license(&[product("0002",200),product("0001",100)],&catalogue(),&request(),1).unwrap();assert_eq!(a.revision,b.revision);
        let tie=map_full_license(&[product("0002",200),product("0001",200)],&catalogue(),&request(),1).unwrap();assert_eq!(tie.sku_store_id,"ABCD1234EFGH/0001");assert_ne!(a.revision,tie.revision);
        let xml=String::from_utf8(encode(Ok(a))).unwrap();assert!(xml.contains("<Status>Available</Status>"));assert!(xml.contains("<ExpirationDate>200</ExpirationDate>"));assert!(!xml.contains("<GameLicense>"));assert!(xml.len()<4096);
    }
    #[test]
    fn unknown_trial_foreign_expired_and_empty_are_not_full_success() {
        assert!(matches!(map_full_license(&[],&catalogue(),&request(),1),Err(Status::NotLicensed)));
        assert!(matches!(map_full_license(&[product("0001",1)],&catalogue(),&request(),1),Err(Status::Expired)));
        assert!(matches!(map_full_license(&[product("9999",200)],&catalogue(),&request(),1),Err(Status::Unsupported)));
        let mut c=catalogue();c["Product"]["DisplaySkuAvailabilities"][0]["Sku"]["Properties"]["IsTrial"]=json!(true);
        assert!(matches!(map_full_license(&[product("0001",200)],&c,&request(),1),Err(Status::Unsupported)));
        let mut r=request();r.package_family_name="Other.Game_publisher".into();assert!(matches!(map_full_license(&[product("0001",200)],&catalogue(),&r,1),Err(Status::Unsupported)));
        let mut c=catalogue();c["Product"]["ProductId"]=json!("OTHER1234567");assert!(matches!(map_full_license(&[product("0001",200)],&c,&request(),1),Err(Status::Error)));
    }
    #[test]
    fn token_expiring_during_catalogue_io_cannot_publish_available() {
        let verified=verified_token::VerifiedToken{products:vec![product("0001",500)],expires_at:100,not_before:10};
        assert!(map_verified_license(&verified,&catalogue(),&request(),99).is_ok());
        assert!(matches!(map_verified_license(&verified,&catalogue(),&request(),100),Err(Status::Expired)));
        assert!(matches!(map_verified_license(&verified,&catalogue(),&request(),9),Err(Status::Expired)));
    }
    fn durable_fixture()->(Request,Value,verified_token::VerifiedToken) {
        let mut r=request();r.durable_store_id=Some("OTHER1234567".into());
        let mut c=catalogue();c["Product"]["ProductId"]=json!("OTHER1234567");c["Product"]["ProductKind"]=json!("Durable");
        c["Product"]["MarketProperties"]=json!([{"RelatedProducts":[{"RelationshipType":"addOnParent","RelatedProductId":r.store_id}]}]);
        let v=verified_token::VerifiedToken{products:vec![verified_token::Product{product_id:"OTHER1234567".into(),sku_id:"0001".into(),ends_at:500}],expires_at:300,not_before:10};
        (r,c,v)
    }
    #[test]
    fn durable_requires_exact_signed_grant_and_title_association() {
        let (r,mut c,mut v)=durable_fixture();
        let good=map_verified_license(&v,&c,&r,100).unwrap();
        assert_eq!(good.sku_store_id,"OTHER1234567/0001");assert_eq!(good.expiration_date,160);
        c["Product"]["MarketProperties"][0]["RelatedProducts"][0]["RelatedProductId"]=json!("FOREIGN12345");
        assert!(matches!(map_verified_license(&v,&c,&r,100),Err(Status::Unsupported)));
        let (_,c,_)=durable_fixture();v.products.clear();
        assert!(matches!(map_verified_license(&v,&c,&r,100),Err(Status::Unavailable)));
    }
    #[test]
    fn durable_never_extends_signed_dates_or_accepts_wrong_product_kinds() {
        let (r,mut c,mut v)=durable_fixture();v.expires_at=130;
        assert_eq!(map_verified_license(&v,&c,&r,100).unwrap().expiration_date,130);
        v.products[0].ends_at=120;
        assert_eq!(map_verified_license(&v,&c,&r,100).unwrap().expiration_date,120);
        assert!(matches!(map_verified_license(&v,&c,&r,120),Err(Status::Unavailable)));
        v.products[0].ends_at=500;c["Product"]["ProductKind"]=json!("UnmanagedConsumable");
        assert!(matches!(map_verified_license(&v,&c,&r,100),Err(Status::Unsupported)));
        let (_,mut c,_)=durable_fixture();c["Product"]["DisplaySkuAvailabilities"][0]["Sku"]["Properties"]["IsTrial"]=json!(true);
        assert!(matches!(map_verified_license(&v,&c,&r,100),Err(Status::Unsupported)));
    }
    #[test]
    fn durable_request_is_optional_bounded_and_distinct_from_the_game() {
        let xml=format!("<StoreGameLicenseRequest><Context>{}</Context><StoreId>ABCD1234EFGH</StoreId><PackageFamilyName>Test.Game_publisher</PackageFamilyName><Market>AT</Market><DurableStoreId>OTHER1234567</DurableStoreId></StoreGameLicenseRequest>","a".repeat(64));
        assert_eq!(parse_request(xml.as_bytes()).unwrap().durable_store_id.as_deref(),Some("OTHER1234567"));
        for bad in [xml.replace("OTHER1234567","ABCD1234EFGH"),xml.replace("OTHER1234567","../wrong"),xml.replace("</DurableStoreId>","</DurableStoreId><DurableStoreId>OTHER1234567</DurableStoreId>")]{assert!(parse_request(bad.as_bytes()).is_err());}
    }
    #[tokio::test]
    async fn valid_cache_needs_no_credentials_but_never_survives_expiry_or_clear() {
        let now=chrono::Utc::now().timestamp();let r=request();let mut cache=LicenseCache::default();
        let license=map_full_license(&[product("0001",now+100)],&catalogue(),&r,now).unwrap();
        cache.cached=Some(Cached{key:(r.context.clone(),r.store_id.clone(),r.package_family_name.clone(),r.market.clone()),observation:Observation{license:license.clone(),_candidates:vec![product("0001",now+100)],jwt_expires_at:now+90,observed_at:now,observed_instant:Instant::now()}});
        let tokens=Arc::new(TokenManager::with_memory());assert_eq!(cache.query(&r,tokens.clone()).await.unwrap().revision,license.revision);
        cache.cached.as_mut().unwrap().observation.jwt_expires_at=now-1;assert!(matches!(cache.query(&r,tokens.clone()).await,Err(Status::Unavailable)));assert!(cache.cached.is_none());
        cache.clear();assert!(matches!(cache.query(&r,tokens).await,Err(Status::Unavailable)));
    }
}
