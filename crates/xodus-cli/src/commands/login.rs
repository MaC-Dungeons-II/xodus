use std::process::ExitCode;

use xodus::models::live::{DAProperty, ExchangeUserTokenOutcome};
use xodus::models::{secrets, soap};
use xodus::tokens::TokenManager;

use crate::webview;

const CLIENT_ID: &str = "000000004424da1f";
const LOGIN_MARKET: &str = "en-US";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0";

#[derive(Debug)]
enum LoginFlowError {
    AccountMismatch,
    MissingChallenge,
}

impl std::fmt::Display for LoginFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AccountMismatch => "Please sign in with the existing Microsoft account",
            Self::MissingChallenge => "Microsoft did not return a supported verification step",
        })
    }
}

impl std::error::Error for LoginFlowError {}

// Only fixed exit codes cross into the launcher. Do not log the error itself:
// network, XML and signature errors can contain account data or response text.
fn failure_code(error: &(dyn std::error::Error + 'static)) -> u8 {
    use xodus::api::live::{RSTError, ResponseStep};
    if let Some(error) = error.downcast_ref::<RSTError>() {
        return match error {
            RSTError::InvalidCredential | RSTError::Base64(_) => 71,
            RSTError::Request(error) if error.is_timeout() => 92,
            RSTError::Request(_) => 73,
            RSTError::AuthenticationRejected => 75,
            RSTError::Serialization(_) | RSTError::Builder(_) => 80,
            RSTError::Deserialization(_) => 83,
            RSTError::MissingNonce | RSTError::HmacKey | RSTError::Bergshamra(_)
                | RSTError::InvalidResponseSignature(_) => 84,
            RSTError::InvalidResponse => 89,
            RSTError::Response { step, .. } => match step {
                ResponseStep::Size => 81,
                ResponseStep::Encoding => 82,
                ResponseStep::Envelope => 83,
                ResponseStep::Signature => 84,
                ResponseStep::ChallengeDecryption => 85,
                ResponseStep::ChallengeXml => 86,
                ResponseStep::BodyDecryption => 87,
                ResponseStep::BodyXml => 88,
                ResponseStep::Shape => 89,
                ResponseStep::HttpStatus => 90,
                ResponseStep::RateLimit => 93,
            },
        };
    }
    match error.downcast_ref::<LoginFlowError>() {
        Some(LoginFlowError::AccountMismatch) => 76,
        Some(LoginFlowError::MissingChallenge) => 79,
        None => 70,
    }
}

pub async fn run(client: &reqwest::Client, tokens: &TokenManager, same_account: bool) -> ExitCode {
    let token = match tokens.get_device_sts_token() {
        Ok(token) => token,
        Err(_) => {
            eprintln!("Microsoft sign-in preparation failed");
            return ExitCode::from(71);
        }
    };
    let secrets::Token::Legacy(token) = token else {
        eprintln!("Invalid STS token");
        return ExitCode::from(71);
    };
    let expected = if same_account { match tokens.get_user() {
        Ok(user) if !user.puid.is_empty() => Some(user.puid),
        Err(xodus::tokens::store::TokenStoreError::NotFound) => None,
        _ => return ExitCode::from(71),
    }} else { None };
    let handler = LoginHandler::new(client.clone(), token, expected);
    let output = match webview::run_sessions(handler) {
        Ok(output) => output.flatten(),
        Err(error) => {
            let code = failure_code(error.as_ref());
            eprintln!("Microsoft sign-in failed (code {code})");
            return ExitCode::from(code);
        }
    };
    let Some((user, body)) = output else { return ExitCode::FAILURE; };
    // Commit only after the complete exchange issued a usable root credential.
    // A closed window or incomplete exchange leaves the existing account intact.
    let root = match xodus::tokens::session::renewed_sts(body) {
        Ok(root) => root,
        Err(_) => {
            eprintln!("Microsoft sign-in failed (code 91)");
            return ExitCode::from(91);
        }
    };
    if tokens.save_user_token(xodus::tokens::PASSPORT_STS.into(), secrets::Token::Legacy(root)).is_err()
        || tokens.save_user(&user).is_err() {
        return ExitCode::from(72);
    }

    println!("Login completed; credentials stored.");
    ExitCode::SUCCESS
}

struct LoginHandler {
    client: reqwest::Client,
    device: xodus::models::secrets::LegacyToken,
    client_id: String,
    expected: Option<String>,
}

impl LoginHandler {
    fn new(
        client: reqwest::Client,
        device: xodus::models::secrets::LegacyToken,
        expected: Option<String>,
    ) -> Self {
        Self {
            client,
            device,
            client_id: CLIENT_ID.to_string(),
            expected,
        }
    }

    fn exchange_user_token(
        &self,
        prop: DAProperty,
    ) -> Result<ExchangeUserTokenOutcome, Box<dyn std::error::Error>> {
        let client = self.client.clone();
        let device_token = self.device.clone();
        let client_id = self.client_id.clone();
        let username = prop.username;
        let inline_ft = prop.sts_inline_flow_token;
        let user_token = xodus::models::secrets::LegacyToken {
            key_name: None,
            token: prop.da_token,
            binary_secret: None,
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: prop.da_start_time,
                expires: prop.da_expires,
            },
        };

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let mut scopes = vec![(
                    USER_AUTH_SCOPE.to_string(),
                    Some(soap::PolicyReference::token_broker()),
                )];

                scopes.push(("http://Passport.NET/tb".to_string(), None));

                xodus::api::live::exchange_user_token(
                    &client,
                    user_token,
                    username,
                    device_token,
                    Some(inline_ft),
                    None,
                    client_id,
                    &scopes,
                )
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            })
        })
    }
}

impl webview::SessionHandler for LoginHandler {
    type Output = Option<(secrets::User, soap::BodyContent)>;

    fn bootstrap(
        &mut self,
        runtime: &mut webview::RuntimeCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        runtime.open_session(webview::login_request(
            self.client_id.clone(),
            LOGIN_MARKET.to_string(),
        ));
        Ok(())
    }

    fn on_token(
        &mut self,
        session_id: webview::SessionId,
        data: DAProperty,
        runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        if self.expected.as_ref().is_some_and(|puid| puid != &data.puid) {
            return Err(LoginFlowError::AccountMismatch.into());
        }
        let exchanged = self.exchange_user_token(data.clone())?;

        match exchanged {
            ExchangeUserTokenOutcome::Fault(pp) => {
                if let Some(auth_url) = pp.as_ref().and_then(soap::PP::interactive_auth_url) {
                    runtime.close_session(session_id);
                    runtime.open_session(webview::finalize_request(auth_url.to_owned()));
                    return Ok(webview::HandlerControl::Continue);
                }

                runtime.close_session(session_id);
                Err(LoginFlowError::MissingChallenge.into())
            }
            ExchangeUserTokenOutcome::Issued(da) => {
                runtime.close_session(session_id);
                Ok(webview::HandlerControl::Complete(Some((
                    secrets::User { puid: data.puid, username: data.username }, da,
                ))))
            }
        }
    }

    fn on_closed(
        &mut self,
        _session_id: webview::SessionId,
        _runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        Ok(webview::HandlerControl::Complete(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xodus::api::live::RSTError;

    #[test]
    fn response_and_verification_failures_are_not_window_errors() {
        for (error, code) in [
            (RSTError::InvalidCredential, 71),
            (RSTError::InvalidResponse, 89),
            (RSTError::MissingNonce, 84),
            (RSTError::InvalidResponseSignature("SYNTHETIC-PRIVATE-RESPONSE".into()), 84),
            (RSTError::AuthenticationRejected, 75),
        ] {
            assert_eq!(failure_code(&error), code);
        }
        assert_eq!(failure_code(&LoginFlowError::AccountMismatch), 76);
        assert_eq!(failure_code(&LoginFlowError::MissingChallenge), 79);
        assert_eq!(failure_code(&std::io::Error::other("window creation")), 70);
    }

    #[test]
    fn request_failure_is_reported_without_its_url_or_response() {
        let error = reqwest::Client::new().get("https://[synthetic-private-value").build().unwrap_err();
        assert_eq!(failure_code(&RSTError::Request(error)), 73);
    }

    #[test]
    fn response_steps_have_unique_codes_without_private_error_text() {
        use xodus::api::live::ResponseStep::*;
        let mut codes = std::collections::HashSet::new();
        for (step, expected) in [(Size, 81), (Encoding, 82), (Envelope, 83), (Signature, 84),
            (ChallengeDecryption, 85), (ChallengeXml, 86), (BodyDecryption, 87),
            (BodyXml, 88), (Shape, 89), (HttpStatus, 90), (RateLimit, 93)]
        {
            let error = RSTError::InvalidResponseSignature("SYNTHETIC-PRIVATE-RESPONSE".into()).at(step);
            assert_eq!(failure_code(&error), expected);
            assert!(codes.insert(expected));
            assert!(!error.to_string().contains("SYNTHETIC-PRIVATE"));
        }
    }
}
