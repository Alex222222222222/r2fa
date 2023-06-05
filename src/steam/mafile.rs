use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaFile {
    pub account_name: String,
    pub device_id: String,
    pub identity_secret: String,
    pub revocation_code: String,
    pub secret_1: String,
    pub serial_number: u64,
    pub server_time: u64,
    pub shared_secret: String,
    pub status: u64,
    pub token_gid: String,
    pub uri: String,
}
