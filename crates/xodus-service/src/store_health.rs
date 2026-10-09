// SPDX-License-Identifier: GPL-3.0-only
//! Explicit read-only check using the same Store brokers as the game. No
//! checkout credentials, purchase endpoints or device provisioning. Expiring
//! credentials are silently renewed through the same broker path as the game.
use crate::{store_account::BrokerStoreAccount, store_collections::model,
    store_inventory, store_license::{self, Status}};
use serde::Deserialize;
use serde_json::json;
use std::{io::{Read, Write}, sync::Arc, time::Duration};
use xodus::tokens::TokenManager;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config { store_id: String, title_id: u32, msa_app_id: String, package_family_name: String, market: String }
fn parse(bytes: &[u8]) -> Result<Config, ()> {
    if bytes.len() > 2048 { return Err(()); }
    let c: Config = serde_json::from_slice(bytes).map_err(|_| ())?;
    if !model::valid_id(&c.store_id, 12) || c.title_id == 0 || !model::valid_app_id(&c.msa_app_id)
        || c.market.len()!=2 || !c.market.bytes().all(|b| b.is_ascii_uppercase())
        || c.package_family_name.is_empty() || c.package_family_name.len()>255
        || !c.package_family_name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) { return Err(()); }
    Ok(c)
}
fn emit(stage: &str, state: &str, code: &str) {
    let value = json!({"stage":stage,"state":state,"code":code});
    let _ = writeln!(std::io::stdout(), "{value}"); let _ = std::io::stdout().flush();
}
fn code(s: Status) -> &'static str { match s {
    Status::Unavailable=>"sign_in_required", Status::Expired=>"expired", Status::NotLicensed=>"not_licensed",
    Status::Unsupported=>"unsupported", Status::InvalidRequest=>"invalid_config", Status::Error=>"connection", Status::Timeout=>"timeout",
} }
#[derive(Deserialize)]
#[serde(rename_all="PascalCase")]
struct Account { status: String, context: Option<String> }
fn account(state: &mut BrokerStoreAccount, tokens: &TokenManager) -> Result<String, &'static str> {
    let bytes=state.response(b"<StoreAccountContextRequest/>", tokens).map_err(|_| "sign_in_required")?;
    let r: Account=quick_xml::de::from_reader(bytes.as_slice()).map_err(|_| "sign_in_required")?;
    match r.status.as_str() {
        "Available" => r.context.filter(|s| s.len()==64).ok_or("sign_in_required"),
        "Expired" => Err("expired"), _=>Err("sign_in_required"),
    }
}
async fn check(c: Config, tokens: Arc<TokenManager>) {
    let mut state=BrokerStoreAccount::default();
    emit("account","running","checking");
    let context=match xodus::tokens::session::ensure_session(&tokens).await {
        Ok(())=>account(&mut state, &tokens), Err(e)=>Err(e.code()),
    };
    emit("account",if context.is_ok(){"passed"}else{"failed"},context.as_ref().err().copied().unwrap_or("local_session"));
    emit("catalog","running","checking");
    let catalog = async {
        let client=reqwest::Client::builder().timeout(Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_|Status::Error)?;
        let v=store_license::fetch_catalogue(&client,&c.store_id,&c.market).await?;
        if v["Product"]["ProductId"]!=c.store_id {return Err(Status::Error);} Ok(())
    }.await;
    emit("catalog",if catalog.is_ok(){"passed"}else{"failed"},catalog.err().map(code).unwrap_or("available"));
    let context=match context { Ok(context)=>context, Err(code)=>{for stage in ["license","library"]{emit(stage,"skipped",code);}return;} };
    emit("license","running","checking");
    let r=store_license::Request {context:context.clone(),store_id:c.store_id.clone(),package_family_name:c.package_family_name,market:c.market.clone(),durable_store_id:None};
    let license=store_license::LicenseCache::default().query(&r,tokens.clone()).await;
    if !state.validate_context(&context,&tokens) {for stage in ["license","library"]{emit(stage,"failed","account_changed");}return;}
    let license=license.and_then(|v|if v.is_active {Ok(())}else{Err(Status::NotLicensed)});
    emit("license",if license.is_ok(){"passed"}else{"failed"},license.err().map(code).unwrap_or("verified"));
    emit("library","running","checking");
    let mut r=store_inventory::Request{context:context.clone(),store_id:c.store_id,title_id:c.title_id,msa_app_id:c.msa_app_id,market:c.market,kinds:31,page_size:100,continuation:String::new()};
    let mut broker=store_inventory::Broker::default();
    let library=async {
        for _ in 0..200 {
            let page=broker.query(&r,tokens.clone()).await?;
            if !page.snapshot.unknown.is_empty() {return Err(Status::Unsupported);}
            if page.continuation.is_empty(){return Ok(());}
            r.continuation=page.continuation;
        }
        Err(Status::Unsupported)
    }.await;
    if !state.validate_context(&context,&tokens) {emit("library","failed","account_changed");return;}
    emit("library",if library.is_ok(){"passed"}else{"failed"},library.err().map(code).unwrap_or("available"));
}
pub async fn run() {
    let mut bytes=Vec::new();
    let config=std::io::stdin().take(2049).read_to_end(&mut bytes).map_err(|_|()).and_then(|_|parse(&bytes));
    let Ok(config)=config else {emit("account","failed","invalid_config");return;};
    if xodus::secrets::init_secrets().is_err(){emit("account","failed","keyring");return;}
    let tokens=Arc::new(TokenManager::with_keychain_and_memory());
    // Isolate dependency panics; no raw error text reaches the launcher.
    let mut work=tokio::spawn(check(config,tokens));
    match tokio::time::timeout(Duration::from_secs(115),&mut work).await {
        Ok(Ok(()))=>(),
        Ok(Err(_))=>emit("check","failed","error"),
        Err(_)=>{work.abort();let _=work.await;emit("check","failed","timeout");},
    }
    xodus::secrets::destroy_secrets();
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn input_is_public_and_bounded() {
        let good=json!({"store_id":"ABCD1234EFGH","title_id":1,"msa_app_id":"0000000012345678","package_family_name":"Game_publisher","market":"AT"});
        assert!(parse(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (key,value) in [("market",json!("<xml>")),("store_id",json!("bad")),("title_id",json!(0)),("package_family_name",json!("../secret")),("token",json!("private"))] {
            let mut bad=good.clone();bad[key]=value;assert!(parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
    #[tokio::test] async fn missing_account_does_not_create_credentials() {
        let tokens=TokenManager::with_memory(); let mut state=BrokerStoreAccount::default();
        assert_eq!(account(&mut state,&tokens).unwrap_err(),"sign_in_required");
        assert!(tokens.get_user_sts_token().is_err());assert!(tokens.get_device_sts_token().is_err());
    }
}
