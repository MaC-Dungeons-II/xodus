//! Store-account-only RPS -> Device/Title/User XSTS, using one in-memory PoP key.
//! No Game-XUser fallback, no invented device identity and no credential writes.
use super::model::Request;
use crate::store_license::Status;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use xal::{
    RequestSigner, SignaturePolicyCache, SigningAlgorithm, extensions::SigningReqwestBuilder,
};
use xodus::{
    models::{live::ExchangeUserTokenOutcome, secrets::Token, soap},
    tokens::TokenManager,
};

pub const URL: &str = "https://collections.mp.microsoft.com/v8.0/collections/b2bLicensePreview";
pub struct Session {
    client: reqwest11::Client,
    signer: RequestSigner,
    authorization: String,
    pub expires_at: i64,
    created: Instant,
    key: (String, u32, String),
}
fn diag(stage: &str, http: u16) {
    if std::env::var_os("XODUS_COLLECTIONS_DIAGNOSTICS").is_some() {
        eprintln!("[collections-broker] stage={stage} http={http}");
    }
}
fn failure(stage: &str) -> Status {
    diag(stage, 0);
    Status::Error
}
async fn bounded(mut response: reqwest11::Response, stage: &str) -> Result<Value, Status> {
    diag(stage, response.status().as_u16());
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Status::Error)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(Status::Unsupported);
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        if stage == "collections" && std::env::var_os("XODUS_COLLECTIONS_DIAGNOSTICS").is_some() {
            // Whitelisted boolean categories only, never the server's message/code.
            let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            for category in [
                "signature",
                "token",
                "sku",
                "satisf",
                "product",
                "auth",
                "json",
                "contract",
                "duplicate",
                "invalid",
            ] {
                eprintln!(
                    "[collections-broker] error_category={category} present={}",
                    u8::from(text.contains(category))
                );
            }
        }
        return Err(match status.as_u16() {
            401 | 403 => Status::Unavailable,
            408 | 429 | 504 => Status::Timeout,
            _ => Status::Error,
        });
    }
    serde_json::from_slice(&bytes).map_err(|_| Status::Unsupported)
}
async fn signed(
    client: &reqwest11::Client,
    signer: &mut RequestSigner,
    url: &str,
    body: &Value,
    authorization: Option<&str>,
) -> Result<Value, Status> {
    let stage = match url {
        "https://device.auth.xboxlive.com/device/authenticate" => "device",
        "https://title.auth.xboxlive.com/title/authenticate" => "title",
        "https://user.auth.xboxlive.com/user/authenticate" => "user",
        "https://xsts.auth.xboxlive.com/xsts/authorize" => "xsts",
        URL => "collections",
        _ => "unknown",
    };
    let policy = signer
        .signature_policy_cache
        .find_policy_for_url(url)
        .await
        .map_err(|_| Status::Unsupported)?
        .ok_or(Status::Unsupported)?;
    if policy.version != 1
        || !policy
            .supported_algorithms
            .contains(&SigningAlgorithm::ES256)
    {
        return Err(Status::Unsupported);
    }
    let body = serde_json::to_vec(body).map_err(|_| Status::Error)?;
    // Keep whole request bodies covered. Current exact-SKU batches are <8 KiB.
    if body.len() > policy.max_body_bytes {
        return Err(Status::Unsupported);
    }
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(body);
    // Xbox auth's contract header does not apply to the Commerce v8 API.
    if url != URL {
        request = request.header("x-xbl-contract-version", "1");
    }
    if let Some(value) = authorization {
        request = request.header("Authorization", value);
    }
    let response = request
        .sign(signer, None)
        .await
        .map_err(|_| failure("sign"))?
        .send()
        .await
        .map_err(|_| failure("http"))?;
    bounded(response, stage).await
}
fn token(value: &Value) -> Result<(String, i64), Status> {
    let token = value
        .get("Token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() < 65536)
        .ok_or(Status::Unsupported)?;
    let expiry = value
        .get("NotAfter")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.timestamp())
        .ok_or(Status::Unsupported)?;
    if expiry <= chrono::Utc::now().timestamp() {
        return Err(Status::Expired);
    }
    Ok((token.into(), expiry))
}
fn compact(response: soap::RequestSecurityTokenResponse) -> Result<(String, i64), Status> {
    let expiry = chrono::DateTime::parse_from_rfc3339(&response.lifetime.expires)
        .map_err(|_| Status::Unsupported)?
        .timestamp();
    if expiry <= chrono::Utc::now().timestamp() {
        return Err(Status::Expired);
    }
    let Token::Compact(token) = Token::from(response) else {
        return Err(Status::Unsupported);
    };
    if token.is_empty() || token.len() > 65536 {
        return Err(Status::Unsupported);
    }
    Ok((token, expiry))
}
impl Session {
    pub fn matches(&self, request: &Request) -> bool {
        self.key
            == (
                request.context.clone(),
                request.title_id,
                request.msa_app_id.clone(),
            )
            && self.created.elapsed() < Duration::from_secs(30)
            && self.expires_at > chrono::Utc::now().timestamp() + 5
    }
    pub async fn create(request: &Request, tokens: &TokenManager) -> Result<Self, Status> {
        Self::create_for(request, tokens, false).await
    }
    pub async fn checkout(request: &Request, tokens: &TokenManager) -> Result<Self, Status> {
        Self::create_for(request, tokens, true).await
    }
    pub fn checkout_token(&self) -> &str { &self.authorization }
    async fn create_for(request: &Request, tokens: &TokenManager, checkout: bool) -> Result<Self, Status> {
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
        let client13 = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Status::Error)?;
        let device_response = xodus::api::live::exchange_device_token(
            &client13,
            device.clone(),
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".into(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".into(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .map_err(|_| failure("device_rps"))?;
        let (device_rps, de) = compact(device_response)?;
        let app = &request.msa_app_id;
        let user_response=xodus::api::live::exchange_user_token(&client13,user,tokens.get_user().map_err(|_|Status::Unavailable)?.username,device,None,Some("Silent".into()),app.clone(),&[(format!("scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0&clientid={app}"),Some(soap::PolicyReference::token_broker()))]).await.map_err(Status::from)?;
        let response = match user_response {
            ExchangeUserTokenOutcome::Issued(
                soap::BodyContent::RequestSecurityTokenResponseCollection(mut c),
            ) if c.security_tokens.len() == 1 => c.security_tokens.remove(0),
            ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
                r,
            )) => *r,
            ExchangeUserTokenOutcome::Fault(pp) => return Err(match xodus::tokens::session::fault(pp.as_ref()) {
            xodus::tokens::session::SessionError::SignInRequired => Status::Expired, _ => Status::Error,
        }),
        _ => return Err(Status::Unsupported),
        };
        let (user_rps, ue) = compact(response)?;
        let client = reqwest11::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest11::redirect::Policy::none())
            .user_agent("xodus-store-collections/0.1")
            .build()
            .map_err(|_| Status::Error)?;
        let policies = bounded(
            client
                .get("https://title.mgt.xboxlive.com/titles/default/endpoints?type=1")
                .header("x-xbl-contract-version", "1")
                .send()
                .await
                .map_err(|_| failure("policy_http"))?,
            "policy",
        )
        .await?;
        // XAL v0.1.3 does not canonicalize additional signed headers. Do not silently
        // accept a future policy requiring them or a non-XBL signature.
        for p in policies
            .get("SignaturePolicies")
            .and_then(Value::as_array)
            .ok_or(Status::Unsupported)?
        {
            if p.get("ExtraHeaders")
                .is_some_and(|v| !v.as_array().is_some_and(|a| a.is_empty()) && !v.is_null())
            {
                return Err(Status::Unsupported);
            }
        }
        let mut signer = RequestSigner::default();
        signer.signature_policy_cache = SignaturePolicyCache::new(
            serde_json::from_value(policies).map_err(|_| Status::Unsupported)?,
        );
        let proof = signer.get_proof_key();
        let d=signed(&client,&mut signer,"https://device.auth.xboxlive.com/device/authenticate",&json!({"RelyingParty":"http://auth.xboxlive.com","TokenType":"JWT","Properties":{"AuthMethod":"RPS","RpsTicket":device_rps,"SiteName":"user.auth.xboxlive.com","Version":"10.0.22621","ProofKey":proof}}),None).await?;
        let (device_token, de2) = token(&d)?;
        let title=signed(&client,&mut signer,"https://title.auth.xboxlive.com/title/authenticate",&json!({"RelyingParty":"http://auth.xboxlive.com","TokenType":"JWT","Properties":{"DeviceToken":device_token,"ProofKey":proof,"TitleId":request.title_id}}),None).await?;
        let tid = title["DisplayClaims"]["xti"]["tid"].as_u64().or_else(|| {
            title["DisplayClaims"]["xti"]["tid"]
                .as_str()
                .and_then(|s| s.parse().ok())
        });
        if tid != Some(request.title_id as u64) {
            return Err(Status::Unavailable);
        }
        let (title_token, te) = token(&title)?;
        let u=signed(&client,&mut signer,"https://user.auth.xboxlive.com/user/authenticate",&json!({"RelyingParty":"http://auth.xboxlive.com","TokenType":"JWT","Properties":{"AuthMethod":"RPS","RpsTicket":user_rps,"SiteName":"user.auth.xboxlive.com"}}),None).await?;
        let (user_token, ue2) = token(&u)?;
        let x=signed(&client,&mut signer,"https://xsts.auth.xboxlive.com/xsts/authorize",&json!({"RelyingParty":if checkout {"http://mp.microsoft.com/"} else {"http://licensing.xboxlive.com"},"TokenType":"JWT","Properties":{"SandboxId":"RETAIL","DeviceToken":device_token,"TitleToken":title_token,"UserTokens":[user_token]}}),None).await?;
        let (token, xe) = token(&x)?;
        let users = x["DisplayClaims"]["xui"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or(Status::Unsupported)?;
        let hash = users[0]["uhs"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(Status::Unsupported)?;
        Ok(Self {
            client,
            signer,
            authorization: format!("XBL3.0 x={hash};{token}"),
            expires_at: [de, ue, de2, te, ue2, xe].into_iter().min().unwrap(),
            created: Instant::now(),
            key: (
                request.context.clone(),
                request.title_id,
                request.msa_app_id.clone(),
            ),
        })
    }
    pub async fn page(&mut self, body: &Value) -> Result<Value, Status> {
        if self.expires_at <= chrono::Utc::now().timestamp() {
            return Err(Status::Expired);
        }
        signed(
            &self.client,
            &mut self.signer,
            URL,
            body,
            Some(&self.authorization),
        )
        .await
    }
}
