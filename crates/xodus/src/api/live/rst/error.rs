#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStep {
    Size,
    Encoding,
    Envelope,
    Signature,
    ChallengeDecryption,
    ChallengeXml,
    BodyDecryption,
    BodyXml,
    Shape,
    HttpStatus,
    RateLimit,
}

#[derive(thiserror::Error, Debug)]
pub enum RSTError {
    // This context is fixed metadata. Never display the source: parser and
    // signature errors may contain credentials, URLs or server response text.
    #[error("Microsoft response processing failed at {step:?}")]
    Response {
        step: ResponseStep,
        #[source]
        source: Box<RSTError>,
    },
    #[error("Microsoft rejected the user credential")]
    AuthenticationRejected,
    #[error("Invalid local credential")]
    InvalidCredential,
    #[error("Invalid token response")]
    InvalidResponse,
    #[error("Error making a request {0:?}")]
    Request(#[from] reqwest::Error),
    #[error("Error serializing request {0:?}")]
    Serialization(#[from] quick_xml::SeError),
    #[error("Error deserializing response {0:?}")]
    Deserialization(#[from] quick_xml::DeError),
    #[error("Unable to decode base64")]
    Base64(#[from] base64::DecodeError),
    #[error("Error processing XML for verification {0:?}")]
    Bergshamra(#[from] bergshamra::Error),
    #[error("Error building RST request {0:?}")]
    Builder(#[from] RSTBuilderError),

    #[error("Response is malformed, unable to find nonce for decryption")]
    MissingNonce,
    #[error("Unexpected error deriving hmac key")]
    HmacKey,
    #[error("Response contains an invalid encrypted payload")]
    InvalidEncryptedPayload,
    #[error("Unable to decrypt response")]
    Decryption,
    #[error("Decrypted response is not valid UTF-8")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("The signature verification failed - {0}")]
    InvalidResponseSignature(String),
}

impl RSTError {
    pub fn at(self, step: ResponseStep) -> Self {
        Self::Response { step, source: Box::new(self) }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RSTBuilderError {
    #[error("Error serializing request")]
    Serialization(#[from] quick_xml::SeError),
    #[error("Error derializing token data")]
    Deserialization(#[from] quick_xml::DeError),
    #[error("Error processing XML for signing {0:?}")]
    Bergshamra(#[from] bergshamra::Error),
    #[error("Builder was provided with invalid set of tokens")]
    UnsupportedTokenCombination,
}
