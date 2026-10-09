use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenRequest {
    pub client_id: String,
    #[serde(default)]
    pub allow_ui: bool,
    #[serde(default, alias = "MSAFullTrust")]
    pub msa_full_trust: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenResponse {
    pub token: String,
    pub expiry: i64,
    pub device_rps: String,
    pub device_expiry: i64,
}

impl MSATokenResponse {
    /// Broker-issued RPS tickets only. Device failure does not turn a valid
    /// user ticket into an invented device identity; native title auth sees
    /// an explicitly unavailable device ticket instead.
    pub fn validated(token: String, expiry: i64, device: Option<(String, i64)>, now: i64) -> Result<Self, &'static str> {
        if token.is_empty() || token.len() > 49152 || expiry <= now {
            return Err("Invalid or expired MSA user ticket");
        }
        let (device_rps, device_expiry) = device
            .filter(|(token, expiry)| !token.is_empty() && token.len() <= 49152 && *expiry > now)
            .unwrap_or_default();
        Ok(Self { token, expiry, device_rps, device_expiry })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn msa_device_fields_are_exact_and_expiry_bound() {
        let response = MSATokenResponse::validated("synthetic-user<&".into(), 200,
            Some(("synthetic-device<&".into(), 201)), 100).unwrap();
        let xml = quick_xml::se::to_string(&response).unwrap();
        assert!(xml.contains("<DeviceRps>synthetic-device&lt;&amp;</DeviceRps>"));
        assert!(xml.contains("<DeviceExpiry>201</DeviceExpiry>"));
        assert!(xml.contains("<Expiry>200</Expiry>"));
        for device in [None, Some(("".into(), 200)), Some(("synthetic".into(), 100)), Some(("synthetic".into(), 99))] {
            let response=MSATokenResponse::validated("synthetic-user".into(),200,device,100).unwrap();
            assert!(response.device_rps.is_empty());
            assert_eq!(response.device_expiry,0);
        }
        assert!(MSATokenResponse::validated("synthetic".into(),100,None,100).is_err());
        assert!(MSATokenResponse::validated("".into(),200,None,100).is_err());
    }
}
