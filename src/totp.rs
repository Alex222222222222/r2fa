use serde::{Deserialize, Serialize};

use crate::HMACType;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TOTPKey {
    /// name
    pub name: String,
    /// key from the user
    pub key: String,
    /// digits
    /// 6, 7, 8
    pub digits: u8,
    /// time step for the key
    pub time_step: u64,
    /// start time, t0
    pub t0: i64,
    /// recovery codes
    pub recovery_codes: Vec<String>,
    /// hmac type
    pub hmac_type: HMACType,
}

impl Default for TOTPKey {
    fn default() -> Self {
        Self {
            name: Default::default(),
            key: Default::default(),
            digits: 6,
            time_step: 30,
            t0: 0,
            recovery_codes: Default::default(),
            hmac_type: Default::default(),
        }
    }
}
