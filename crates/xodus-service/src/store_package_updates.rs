//! Online check of Flightdeck's single registered MSIXVC base package.
//! No installed DLC is inferred from ownership. Newer revisions remain an
//! explicit error until update-policy metadata and package installation exist.
use crate::store_license::{self, Status};
use quick_xml::{Reader, events::Event};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use xodus::{
    models::{live::ExchangeUserTokenOutcome, secrets::Token, soap},
    tokens::TokenManager,
};

#[derive(Clone, Deserialize)]
#[serde(
    rename = "StorePackageUpdatesRequest",
    rename_all = "PascalCase",
    deny_unknown_fields
)]
pub struct Request {
    pub context: String,
    pub store_id: String,
    pub package_family_name: String,
    pub market: String,
    pub version: String,
    pub scope: String,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Current,
    DifferentRevision,
}
fn version(s: &str) -> Option<[u16; 4]> {
    let parts = s.split('.').collect::<Vec<_>>();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        out[i] = p.parse().ok()?;
    }
    Some(out)
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
pub fn parse_request(bytes: &[u8]) -> Result<Request, Status> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() || bytes.len() > 2048 || bytes.contains(&0) {
        return Err(Status::InvalidRequest);
    }
    let mut reader = Reader::from_reader(bytes);
    let mut depth = 0;
    let mut roots = 0;
    loop {
        match reader.read_event().map_err(|_| Status::InvalidRequest)? {
            Event::Start(e) => {
                if e.attributes().next().is_some() || depth > 1 {
                    return Err(Status::InvalidRequest);
                }
                if depth == 0 {
                    if e.name().as_ref() != "StorePackageUpdatesRequest" {
                        return Err(Status::InvalidRequest);
                    }
                    roots += 1;
                } else if ![
                    "Context",
                    "StoreId",
                    "PackageFamilyName",
                    "Market",
                    "Version",
                    "Scope",
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
    if roots != 1 || depth != 0 {
        return Err(Status::InvalidRequest);
    }
    let r: Request = quick_xml::de::from_reader(bytes).map_err(|_| Status::InvalidRequest)?;
    if r.context.len() != 64
        || !r
            .context
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || r.store_id.len() != 12
        || !r
            .store_id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        || r.package_family_name.is_empty()
        || r.package_family_name.len() > 64
        || !r
            .package_family_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        || r.market.len() != 2
        || !r.market.bytes().all(|b| b.is_ascii_uppercase())
        || version(&r.version).is_none()
        || r.scope != "FlightdeckBaseGameOnlyV1"
    {
        return Err(Status::InvalidRequest);
    }
    Ok(r)
}
pub fn encode(result: Result<Outcome, Status>) -> Vec<u8> {
    let status = match result {
        Ok(Outcome::Current) => "Current".into(),
        Ok(Outcome::DifferentRevision) => "DifferentRevision".into(),
        Err(s) => format!("{s:?}"),
    };
    format!("<StorePackageUpdatesResponse><Status>{status}</Status></StorePackageUpdatesResponse>")
        .into_bytes()
}
fn content_id(c: &Value, r: &Request) -> Result<String, Status> {
    let p = &c["Product"];
    if p["ProductId"].as_str() != Some(&r.store_id) || p["ProductKind"].as_str() != Some("Game") {
        return Err(Status::Unsupported);
    }
    let mut ids = BTreeSet::new();
    for item in p["DisplaySkuAvailabilities"]
        .as_array()
        .ok_or(Status::Unsupported)?
    {
        let sku = &item["Sku"];
        let properties = &sku["Properties"];
        if sku["SkuType"] != "full"
            || properties["IsTrial"] != false
            || properties["IsPreOrder"] != false
            || properties["IsBundle"] != false
        {
            continue;
        }
        for package in properties["Packages"]
            .as_array()
            .ok_or(Status::Unsupported)?
        {
            if package["PackageFamilyName"].as_str() == Some(&r.package_family_name)
                && package["PackageFormat"] == "MSIXVC"
                && package["PlatformDependencies"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|v| v["PlatformName"] == "Windows.Desktop"))
            {
                let id = package["ContentId"]
                    .as_str()
                    .filter(|s| uuid(s))
                    .ok_or(Status::Unsupported)?;
                ids.insert(id.to_ascii_lowercase());
            }
        }
    }
    if ids.len() != 1 {
        return Err(Status::Unsupported);
    }
    Ok(ids.into_iter().next().ok_or(Status::Unsupported)?)
}
fn classify(p: &Value, content: &str, installed: &str) -> Result<Outcome, Status> {
    if p["PackageFound"] != true
        || p["ContentId"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .as_deref()
            != Some(content)
        || p["UpdatePredownload"] != false
    {
        return Err(Status::Unsupported);
    }
    let revision = p["VersionId"].as_str().ok_or(Status::Unsupported)?;
    let raw = p["Version"].as_str().ok_or(Status::Unsupported)?;
    let latest = if let Some(v) = version(raw) {
        if !uuid(revision) {
            return Err(Status::Unsupported);
        }
        v
    } else {
        let (v, id) = raw.rsplit_once('.').ok_or(Status::Unsupported)?;
        if revision != raw || !uuid(id) {
            return Err(Status::Unsupported);
        }
        version(v).ok_or(Status::Unsupported)?
    };
    let files = p["PackageFiles"].as_array().ok_or(Status::Unsupported)?;
    let images = files
        .iter()
        .filter(|f| {
            f["FileName"]
                .as_str()
                .is_some_and(|s| s.ends_with(".msixvc"))
        })
        .collect::<Vec<_>>();
    if images.len() != 1 {
        return Err(Status::Unsupported);
    }
    let file = images[0];
    if file["ContentId"]
        .as_str()
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some(content)
        || file["VersionId"].as_str() != Some(revision)
        || !file["FileSize"]
            .as_u64()
            .is_some_and(|n| n > 0 && n < 8 * 1024u64.pow(4))
    {
        return Err(Status::Unsupported);
    }
    let installed = version(installed).ok_or(Status::InvalidRequest)?;
    // Neither server rollback nor a future installation becomes "no updates".
    Ok(if latest == installed {
        Outcome::Current
    } else {
        Outcome::DifferentRevision
    })
}
async fn observe(r: &Request, tokens: &TokenManager) -> Result<Outcome, Status> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Status::Error)?;
    let catalogue = store_license::fetch_catalogue(&client, &r.store_id, &r.market).await?;
    let content = content_id(&catalogue, r)?;
    let Token::Legacy(device) = tokens
        .get_device_sts_token()
        .map_err(|_| Status::Unavailable)?
    else {
        return Err(Status::Unavailable);
    };
    let Token::Legacy(user) = tokens
        .get_user_sts_token()
        .map_err(|_| Status::Unavailable)?
    else {
        return Err(Status::Unavailable);
    };
    let exchange = xodus::api::live::exchange_user_token(
        &client,
        user,
        "USERNAME".into(),
        device,
        None,
        Some("Silent".into()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".into(),
        &[(
            "user.auth.xboxlive.com".into(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(Status::from)?;
    let issued = match exchange {
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut c),
        ) if c.security_tokens.len() == 1 => c.security_tokens.remove(0),
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(r)) => *r,
        ExchangeUserTokenOutcome::Fault(pp) => return Err(match xodus::tokens::session::fault(pp.as_ref()) {
            xodus::tokens::session::SessionError::SignInRequired => Status::Expired, _ => Status::Error,
        }),
        _ => return Err(Status::Unavailable),
    };
    if chrono::DateTime::parse_from_rfc3339(&issued.lifetime.expires)
        .map_err(|_| Status::Unsupported)?
        .timestamp()
        <= chrono::Utc::now().timestamp()
    {
        return Err(Status::Expired);
    }
    let Token::Compact(rps) = Token::from(issued) else {
        return Err(Status::Unsupported);
    };
    let user = xodus::api::xbox::authenticate_xbox_user(&client, rps)
        .await
        .map_err(|_| Status::Unavailable)?;
    if user.not_after <= chrono::Utc::now() {
        return Err(Status::Expired);
    }
    let auth =
        xodus::api::xbox::request_xsts_token(&client, user.token, "http://update.xboxlive.com")
            .await
            .map_err(|_| Status::Unavailable)?;
    if auth.not_after <= chrono::Utc::now() || auth.token.is_empty() {
        return Err(Status::Expired);
    }
    let uhs = auth
        .user_hash()
        .filter(|s| !s.is_empty())
        .ok_or(Status::Unsupported)?;
    let response = client
        .get(format!(
            "https://packagespc.xboxlive.com/GetBasePackage/{content}"
        ))
        .header("x-xbl-contract-version", "3")
        .header("Authorization", format!("XBL3.0 x={uhs};{}", auth.token))
        .send()
        .await
        .map_err(|_| Status::Error)?;
    let mut response = response.error_for_status().map_err(|_| Status::Error)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Status::Error)? {
        if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err(Status::Unsupported);
        }
        bytes.extend_from_slice(&chunk);
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| Status::Unsupported)?;
    classify(&value, &content, &r.version)
}
pub async fn query(r: Request, tokens: Arc<TokenManager>) -> Result<Outcome, Status> {
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(async move { observe(&r, &tokens).await });
    match tokio::time::timeout(Duration::from_secs(35), workers.join_next()).await {
        Ok(Some(Ok(result))) => result,
        Ok(_) => Err(Status::Error),
        Err(_) => {
            workers.abort_all();
            while workers.join_next().await.is_some() {}
            Err(Status::Timeout)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const ID: &str = "11111111-2222-4333-8444-555555555555";
    fn request() -> Request {
        Request {
            context: "a".repeat(64),
            store_id: "GAME1234EFGH".into(),
            package_family_name: "Test.Game_publisher".into(),
            market: "AT".into(),
            version: "1.2.3.4".into(),
            scope: "FlightdeckBaseGameOnlyV1".into(),
        }
    }
    fn package() -> Value {
        let revision = format!("1.2.3.4.{ID}");
        json!({"PackageFound":true,"ContentId":ID,"Version":revision,"VersionId":revision,"UpdatePredownload":false,"PackageFiles":[{"FileName":"game.msixvc","FileSize":4096,"ContentId":ID,"VersionId":revision,"KeyBlob":"PRIVATE_KEY","RelativeUrl":"PRIVATE_URL"}]})
    }
    #[test]
    fn revisions_are_compared_without_guessing_update_policy() {
        let p = package();
        assert_eq!(classify(&p, ID, "1.2.3.4").unwrap(), Outcome::Current);
        for s in ["1.2.3.3", "1.2.3.5"] {
            assert_eq!(classify(&p, ID, s).unwrap(), Outcome::DifferentRevision);
        }
    }
    #[test]
    fn malformed_or_unavailable_is_never_current() {
        for (key, value) in [
            ("PackageFound", json!(false)),
            ("ContentId", json!("other")),
            ("UpdatePredownload", json!(true)),
            ("VersionId", json!(ID)),
            ("Version", json!("1.2")),
            ("PackageFiles", json!([])),
        ] {
            let mut p = package();
            p[key] = value;
            assert!(classify(&p, ID, "1.2.3.4").is_err());
        }
        for (key, value) in [
            ("FileSize", json!(0)),
            ("VersionId", json!(ID)),
            ("ContentId", json!("other")),
        ] {
            let mut p = package();
            p["PackageFiles"][0][key] = value;
            assert!(classify(&p, ID, "1.2.3.4").is_err());
        }
    }
    #[test]
    fn scope_and_xml_are_strict() {
        let r = request();
        let xml = format!(
            "<StorePackageUpdatesRequest><Context>{}</Context><StoreId>{}</StoreId><PackageFamilyName>{}</PackageFamilyName><Market>AT</Market><Version>1.2.3.4</Version><Scope>FlightdeckBaseGameOnlyV1</Scope></StorePackageUpdatesRequest>",
            r.context, r.store_id, r.package_family_name
        );
        assert!(parse_request(xml.as_bytes()).is_ok());
        for bad in [
            xml.replace("FlightdeckBaseGameOnlyV1", "all"),
            xml.replace("1.2.3.4", "65536.2.3.4"),
            xml.replace("</Version>", "</Version><Version>1.2.3.4</Version>"),
            format!("<!DOCTYPE x>{xml}"),
            format!("{xml}{xml}"),
            xml.replace("<Market>", "<Market value='x'>"),
        ] {
            assert!(parse_request(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn no_package_secrets_in_result() {
        assert_eq!(
            String::from_utf8(encode(Ok(Outcome::Current))).unwrap(),
            "<StorePackageUpdatesResponse><Status>Current</Status></StorePackageUpdatesResponse>"
        );
        assert!(
            !String::from_utf8(encode(Err(Status::Error)))
                .unwrap()
                .contains("PRIVATE")
        );
    }
    #[test]
    fn exact_pc_package_required() {
        let r = request();
        let package = json!({"PackageFamilyName":r.package_family_name,"PackageFormat":"MSIXVC","ContentId":ID,"PlatformDependencies":[{"PlatformName":"Windows.Desktop"}]});
        let mut c = json!({"Product":{"ProductId":r.store_id,"ProductKind":"Game","DisplaySkuAvailabilities":[{"Sku":{"SkuType":"full","Properties":{"IsTrial":false,"IsPreOrder":false,"IsBundle":false,"Packages":[package]}}}]}});
        assert_eq!(content_id(&c, &r).unwrap(), ID);
        c["Product"]["DisplaySkuAvailabilities"][0]["Sku"]["Properties"]["Packages"][0]["PackageFamilyName"] =
            json!("Wrong_family");
        assert!(content_id(&c, &r).is_err());
    }
}
