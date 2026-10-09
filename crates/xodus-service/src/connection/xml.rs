use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::models::xgameruntime::xuser::{MSATokenRequest, MSATokenResponse};
use xodus::proto::xodus::XodusMessageType;

use crate::XML_MAGIC;
use crate::simple_context::SimpleContext;

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    tracing::debug!("Parsing XML");
    let message_type = socket.read_u16_le().await?;
    let message_size = socket.read_u16_le().await?;
    let mut buffer = vec![0; message_size as usize];
    tracing::debug!("Reading buffer {message_size}");
    socket.read_exact(&mut buffer).await?;
    tracing::debug!("Read buffer");
    let message_type = XodusMessageType::try_from(message_type as i32).unwrap_or_default();

    let out_buf = match parse_message(context, message_type, buffer).await {
        Ok(buf) => buf,
        Err(_) => {
            // Parser errors can contain input excerpts, including auth material.
            tracing::error!("Failed parsing IPC message");
            vec![]
        }
    };

    let data = super::encode_message(XML_MAGIC, message_type as u16 + 1, out_buf);
    socket.write_all(&data).await
}

pub async fn parse_message(
    context: &mut SimpleContext,
    message_type: XodusMessageType,
    buffer: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match message_type {
        XodusMessageType::StorePurchaseRequest => {
            use crate::store_purchase;
            let request = match store_purchase::parse(&buffer) {
                Ok(r) => r, Err(_) => return Ok(store_purchase::encode("InvalidRequest")),
            };
            let tokens = context.tokens().clone();
            if let Err(status) = context.store_account.prepare(&request.context, &tokens).await {
                context.store_purchase.cancel(); return Ok(store_purchase::encode(&format!("{status:?}")));
            }
            let account = request.context.clone();
            let result = context.store_purchase.handle(request, tokens.clone()).await;
            if result != store_purchase::encode("Pending") && result != store_purchase::encode("Busy") {
                // A completed or interrupted dialog may have changed ownership.
                // Never answer the game's next query with pre-checkout absence.
                context.store_collections.clear();
                context.store_inventory.clear();
                context.store_license.clear();
            }
            if !context.store_account.validate_context(&account, &tokens) {
                context.store_purchase.cancel(); return Ok(store_purchase::encode("Unavailable"));
            }
            Ok(result)
        }
        XodusMessageType::Ping => Ok(buffer),
        XodusMessageType::StoreAccountContextRequest => {
            let tokens = context.tokens().clone();
            context.store_account.session_response(&buffer, &tokens).await
                .map_err(|_| "Invalid store-account request".into())
        }
        XodusMessageType::StoreGameLicenseRequest => {
            use crate::store_license::{self,Status};
            let request=match store_license::parse_request(&buffer) {
                Ok(request)=>request,
                Err(status)=>return Ok(store_license::encode(Err(status))),
            };
            let tokens=context.tokens().clone();
            if let Err(status)=context.store_account.prepare(&request.context,&tokens).await {
                context.store_license.clear();
                return Ok(store_license::encode(Err(status)));
            }
            let result=context.store_license.query(&request,tokens.clone()).await;
            if !context.store_account.validate_context(&request.context,&tokens) {
                context.store_license.clear();
                return Ok(store_license::encode(Err(Status::Unavailable)));
            }
            Ok(store_license::encode(result))
        }
        XodusMessageType::StoreLicenseTokenRequest => {
            use crate::store_license::{Status};
            use crate::store_license_token;
            let request=match store_license_token::parse_request(&buffer) {
                Ok(request)=>request,
                Err(status)=>return Ok(store_license_token::encode(Err(status))),
            };
            let tokens=context.tokens().clone();
            if let Err(status)=context.store_account.prepare(&request.context,&tokens).await {
                context.store_license.clear();
                return Ok(store_license_token::encode(Err(status)));
            }
            let result=store_license_token::query(request.clone(),tokens.clone()).await;
            if !context.store_account.validate_context(&request.context,&tokens) {
                context.store_license.clear();
                return Ok(store_license_token::encode(Err(Status::Unavailable)));
            }
            Ok(store_license_token::encode(result))
        }
        XodusMessageType::StoreCollectionsRequest => {
            use crate::{store_collections,store_license::Status};
            let request=match store_collections::parse_request(&buffer) {
                Ok(request)=>request,
                Err(status)=>return Ok(store_collections::encode(Err(status))),
            };
            let tokens=context.tokens().clone();
            if let Err(status)=context.store_account.prepare(&request.context,&tokens).await {
                context.store_collections.clear();
                return Ok(store_collections::encode(Err(status)));
            }
            let result=context.store_collections.query(&request,tokens.clone()).await;
            if !context.store_account.validate_context(&request.context,&tokens) {
                context.store_collections.clear();
                return Ok(store_collections::encode(Err(Status::Unavailable)));
            }
            Ok(store_collections::encode(result))
        }
        XodusMessageType::StoreInventoryRequest => {
            use crate::{store_inventory,store_license::Status};
            let request=match store_inventory::parse_request(&buffer) {
                Ok(request)=>request,
                Err(status)=>return Ok(store_inventory::encode(Err(status))),
            };
            let tokens=context.tokens().clone();
            if let Err(status)=context.store_account.prepare(&request.context,&tokens).await {
                context.store_inventory.clear();
                return Ok(store_inventory::encode(Err(status)));
            }
            let result=context.store_inventory.query(&request,tokens.clone()).await;
            if !context.store_account.validate_context(&request.context,&tokens) {
                context.store_inventory.clear();
                return Ok(store_inventory::encode(Err(Status::Unavailable)));
            }
            Ok(store_inventory::encode(result))
        }
        XodusMessageType::StorePackageUpdatesRequest => {
            use crate::{store_package_updates, store_license::Status};
            let request=match store_package_updates::parse_request(&buffer) {
                Ok(request)=>request,
                Err(status)=>return Ok(store_package_updates::encode(Err(status))),
            };
            let tokens=context.tokens().clone();
            if let Err(status)=context.store_account.prepare(&request.context,&tokens).await {
                return Ok(store_package_updates::encode(Err(status)));
            }
            let result=store_package_updates::query(request.clone(),tokens.clone()).await;
            if !context.store_account.validate_context(&request.context,&tokens) {
                return Ok(store_package_updates::encode(Err(Status::Unavailable)));
            }
            Ok(store_package_updates::encode(result))
        }
        XodusMessageType::MsaTokenRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<MSATokenRequest>(string_buf)?;
            xodus::tokens::session::ensure_session(context.tokens()).await?;
            let account = context.tokens().get_user()?;
            let Token::Legacy(token) = context.tokens().get_user_sts_token()? else {
                return Ok(vec![]);
            };
            let scope = if req.msa_full_trust {
                "service::user.auth.xboxlive.com::MBI_SSL"
            } else {
                "xboxlive.signin"
            };
            let Token::Legacy(device_token) = context.tokens().get_device_sts_token()? else { return Err("Missing broker device ticket".into()); };
            let device_token_resp = xodus::api::live::exchange_device_token(
                &context.client,
                device_token.clone(),
                "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
                "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
                Some(soap::PolicyReference::token_broker()),
            )
            .await;

            let ms_device_rps_token = if let Some((Ok(ms_device_token), Ok(lifetime))) =
                device_token_resp.ok().map(|t| {
                    let expiry = chrono::DateTime::parse_from_rfc3339(&t.lifetime.expires);
                    (compact(t), expiry)
                }) {
                Some((ms_device_token, lifetime.timestamp()))
            } else {
                None
            };

            let user_token = xodus::api::live::exchange_user_token(
                &context.client,
                token,
                account.username,
                device_token.clone(),
                None,
                Some("Silent".to_string()),
                req.client_id.clone(),
                &[
                    (
                        format!("scope={scope}&api-version=2.0&clientid={}", req.client_id),
                        Some(soap::PolicyReference::token_broker()),
                    ),
                ],
            )
            .await?;

            let body = match user_token {
                ExchangeUserTokenOutcome::Issued(body) => body,
                ExchangeUserTokenOutcome::Fault(pp) => return Err(xodus::tokens::session::fault(pp.as_ref()).into()),
            };
            if context.tokens().get_user()?.puid != account.puid { return Err("Account changed during MSA exchange".into()); }
            let token = match body {
                soap::BodyContent::RequestSecurityTokenResponse(token) => *token,
                soap::BodyContent::RequestSecurityTokenResponseCollection(mut c) if c.security_tokens.len()==1 => c.security_tokens.remove(0),
                _ => return Err("Invalid MSA token response".into()),
            };
            let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)?;
            let payload = MSATokenResponse::validated(
                compact(token)?, expiry.timestamp(), ms_device_rps_token,
                chrono::Utc::now().timestamp(),
            )?;
            let payload = quick_xml::se::to_string(&payload)?;
            if payload.len() > u16::MAX as usize { return Err("MSA response exceeds IPC frame".into()); }
            Ok(payload.as_bytes().to_vec())
        }
        _ => Err("Unimplemented".into()),
    }
}

fn compact(token: soap::RequestSecurityTokenResponse) -> Result<String, &'static str> {
    let value = token.requested_security_token.binary_security_token.ok_or("Missing compact ticket")?.value;
    if value.is_empty() || value.len()>60000 { return Err("Invalid compact ticket"); }
    match token.token_type.as_str() {
        "urn:passport:compact" => Ok(value),
        "urn:passport:delegationcompact" => Ok(format!("d={value}")),
        _ => Err("Invalid compact ticket type"),
    }
}
