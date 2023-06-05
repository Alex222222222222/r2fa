use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::{error, HMACType, Key, OtpAuthKey};

/// TOTPKey is the key for the TOTP,
/// TOTP is the time based key,
///
/// usage:
/// ```rust
/// use libr2fa::TOTPKey;
/// use libr2fa::HMACType;
/// use libr2fa::Key;
///
/// let mut totp_key1 = TOTPKey {
///     key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
///     hmac_type: HMACType::SHA1,
///     ..Default::default()
/// };
///
/// let code = totp_key1.get_code().unwrap();
///
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// issuer
    pub issuer: Option<String>,
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
            issuer: Default::default(),
        }
    }
}

impl TOTPKey {
    fn decode_key(&self) -> Result<Rc<[u8]>, error::Error> {
        let key = data_encoding::BASE32.decode(self.get_key().as_bytes());
        if key.is_err() {
            return Err(error::Error::InvalidKey);
        }

        Ok(Rc::from(key.unwrap().as_slice()))
    }

    fn get_key(&self) -> &str {
        &self.key
    }
}

impl OtpAuthKey for TOTPKey {
    fn to_uri_struct(&self) -> crate::URI {
        crate::URI {
            name: self.name.clone(),
            issuer: self.issuer.clone(),
            secret: self.key.clone(),
            algorithm: Some(self.hmac_type),
            digits: Some(self.digits),
            period: Some(self.time_step),
            counter: None,
            key_type: crate::KeyType::TOTP,
        }
    }

    fn from_uri_struct(uri: &crate::URI) -> Result<Box<dyn Key>, crate::Error> {
        let time_step = if let Some(time_step) = uri.period {
            time_step
        } else {
            30
        };
        let digits = if let Some(digits) = uri.digits {
            digits
        } else {
            6
        };
        let algorithm = if let Some(algorithm) = uri.algorithm {
            algorithm
        } else {
            HMACType::default()
        };

        Ok(Box::from(TOTPKey {
            name: uri.name.clone(),
            issuer: uri.issuer.clone(),
            key: uri.secret.clone(),
            digits,
            time_step,
            t0: 0,
            recovery_codes: Vec::default(),
            hmac_type: algorithm,
        }))
    }

    fn get_issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }
}

impl Key for TOTPKey {
    fn get_code(&mut self) -> Result<String, error::Error> {
        let raw = self.decode_key()?;
        let c = (chrono::Utc::now().timestamp() - self.t0) / self.time_step as i64;
        let c = c as u64;
        let c = c.to_be_bytes();

        let res = self.hmac_type.get_hash(raw.as_ref(), &c)?;
        let offset: usize = (res[res.len() - 1] & 0x0f) as usize;

        let code: u32 = (((res[offset] & 0x7f) as u32) << 24)
            | ((res[offset + 1] as u32) << 16)
            | ((res[offset + 2] as u32) << 8)
            | (res[offset + 3] as u32);

        // trim to the number of digits
        let code = code % 10u32.pow(self.digits as u32);

        let mut code = code.to_string();
        // padding 0
        while code.len() < self.digits as usize {
            code.insert(0, '0');
        }

        Ok(code)
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_recovery_codes(&self) -> Vec<String> {
        self.recovery_codes.clone()
    }

    fn get_type(&self) -> crate::KeyType {
        crate::KeyType::TOTP
    }

    fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }

    fn set_recovery_codes(&mut self, recovery_codes: Vec<String>) {
        self.recovery_codes = recovery_codes.to_vec();
    }
}
