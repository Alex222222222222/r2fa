use serde::{Deserialize, Serialize};

use super::token;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamGuardAccount {
    pub account_name: String,
    pub serial_number: String,
    pub revocation_code: String,
    pub shared_secret: token::TwoFactorSecret,
    pub token_gid: String,
    pub identity_secret: String,
    pub server_time: u64,
    pub uri: String,
    pub fully_enrolled: bool,
    pub device_id: String,
    pub secret_1: String,
    pub session: Option<super::steam_api::Session>,
}
