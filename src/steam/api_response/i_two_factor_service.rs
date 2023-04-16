// use crate::{token::TwoFactorSecret, SteamGuardAccount};
use super::super::mobile_web_auth::SteamGuardAccount;
use super::super::token::TwoFactorSecret;

use serde::{Deserialize, Serialize};

/// Represents the response from `/ITwoFactorService/QueryTime/v0001`
///
/// Example Response:
/// ```json
/// {
///   "response": {
///     "server_time": "1655768666",
///     "skew_tolerance_seconds": "60",
///     "large_time_jink": "86400",
///     "probe_frequency_seconds": 3600,
///     "adjusted_time_probe_frequency_seconds": 300,
///     "hint_probe_frequency_seconds": 60,
///     "sync_timeout": 60,
///     "try_again_seconds": 900,
///     "max_attempts": 3
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTimeResponse {
    /// The time that the server will use to check your two factor code.
    pub server_time: u64,
    pub skew_tolerance_seconds: u64,
    pub large_time_jink: u64,
    pub probe_frequency_seconds: u64,
    pub adjusted_time_probe_frequency_seconds: u64,
    pub hint_probe_frequency_seconds: u64,
    pub sync_timeout: u64,
    pub try_again_seconds: u64,
    pub max_attempts: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddAuthenticatorResponse {
    /// Shared secret between server and authenticator
    #[serde(default)]
    pub shared_secret: String,
    /// Authenticator serial number (unique per token)
    #[serde(default)]
    pub serial_number: String,
    /// code used to revoke authenticator
    #[serde(default)]
    pub revocation_code: String,
    /// URI for QR code generation
    #[serde(default)]
    pub uri: String,
    /// Current server time
    #[serde(default)]
    pub server_time: u64,
    /// Account name to display on token client
    #[serde(default)]
    pub account_name: String,
    /// Token GID assigned by server
    #[serde(default)]
    pub token_gid: String,
    /// Secret used for identity attestation (e.g., for eventing)
    #[serde(default)]
    pub identity_secret: String,
    /// Spare shared secret
    #[serde(default)]
    pub secret_1: String,
    /// Result code
    pub status: i32,
    #[serde(default)]
    pub phone_number_hint: Option<String>,
}

impl AddAuthenticatorResponse {
    // TODO dead code
    #[allow(dead_code)]
    pub fn to_steam_guard_account(&self) -> SteamGuardAccount {
        SteamGuardAccount {
            shared_secret: TwoFactorSecret::parse_shared_secret(self.shared_secret.clone())
                .unwrap(),
            serial_number: self.serial_number.clone(),
            revocation_code: self.revocation_code.clone(),
            uri: self.uri.clone(),
            server_time: self.server_time,
            account_name: self.account_name.clone(),
            token_gid: self.token_gid.clone(),
            identity_secret: self.identity_secret.clone(),
            secret_1: self.secret_1.clone(),
            fully_enrolled: false,
            device_id: "".into(),
            session: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FinalizeAddAuthenticatorResponse {
    pub status: i32,
    pub server_time: u64,
    pub want_more: bool,
    pub success: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveAuthenticatorResponse {
    pub success: bool,
}

// #[cfg(test)]
// mod test {
// use super::*;
// use crate::api_responses::SteamApiResponse;
//
// #[test]
// fn test_parse_add_auth_response() {
// let result = serde_json::from_str::<SteamApiResponse<AddAuthenticatorResponse>>(
// include_str!("../fixtures/api-responses/add-authenticator-1.json"),
// );
//
// assert!(
// matches!(result, Ok(_)),
// "got error: {}",
// result.unwrap_err()
// );
// let resp = result.unwrap().response;
//
// assert_eq!(resp.server_time, 1628559846);
// assert_eq!(resp.shared_secret, "wGwZx=sX5MmTxi6QgA3Gi");
// assert_eq!(resp.revocation_code, "R123456");
// }
//
// #[test]
// fn test_parse_add_auth_response2() {
// let result = serde_json::from_str::<SteamApiResponse<AddAuthenticatorResponse>>(
// include_str!("../fixtures/api-responses/add-authenticator-2.json"),
// );
//
// assert!(
// matches!(result, Ok(_)),
// "got error: {}",
// result.unwrap_err()
// );
// let resp = result.unwrap().response;
//
// assert_eq!(resp.status, 29);
// }
// }
