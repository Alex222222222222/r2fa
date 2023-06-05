use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::{error, HMACType, Key, OtpAuthKey};

/// HOTPKey is the key for the HOTP,
/// HOTP is the counter based key,
/// each time you get a code, the counter will increase by 1,
/// the counter is stored in the key
///
/// usage:
/// ```rust
/// use libr2fa::HOTPKey;
/// use libr2fa::HMACType;
/// use libr2fa::Key;
///
/// let mut hotp_key = HOTPKey {
///     key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
///     hmac_type: HMACType::SHA1,
///     ..Default::default()
/// };
///
/// let code = hotp_key.get_code().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HOTPKey {
    /// name
    pub name: String,
    /// key from the user
    pub key: String,
    /// digits
    /// 6, 7, 8
    pub digits: u8,
    /// counter
    pub counter: u64,
    /// recovery codes
    pub recovery_codes: Vec<String>,
    /// hmac type
    pub hmac_type: HMACType,
    /// issuer
    pub issuer: Option<String>,
}

impl Default for HOTPKey {
    fn default() -> Self {
        Self {
            name: Default::default(),
            key: Default::default(),
            digits: 6,
            counter: Default::default(),
            recovery_codes: Default::default(),
            hmac_type: Default::default(),
            issuer: Default::default(),
        }
    }
}

impl HOTPKey {
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

impl OtpAuthKey for HOTPKey {
    fn to_uri_struct(&self) -> crate::URI {
        crate::URI {
            name: self.name.clone(),
            secret: self.key.clone(),
            issuer: self.issuer.clone(),
            algorithm: Some(self.hmac_type),
            digits: Some(self.digits),
            period: None,
            counter: Some(self.counter),
            key_type: crate::KeyType::TOTP,
        }
    }

    fn from_uri_struct(uri: &crate::URI) -> Result<Box<dyn Key>, crate::Error> {
        let counter = if let Some(counter) = uri.counter {
            counter
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
            HMACType::SHA1
        };

        Ok(Box::from(HOTPKey {
            name: uri.name.clone(),
            key: uri.secret.clone(),
            digits,
            counter,
            recovery_codes: Vec::default(),
            hmac_type: algorithm,
            issuer: uri.issuer.clone(),
        }))
    }

    fn get_issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }
}

impl Key for HOTPKey {
    fn get_type(&self) -> crate::KeyType {
        crate::KeyType::HOTP
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_recovery_codes(&self) -> Vec<String> {
        self.recovery_codes.clone()
    }

    fn get_code(&mut self) -> Result<String, error::Error> {
        let raw = self.decode_key()?;
        self.counter += 1;

        let res = self
            .hmac_type
            .get_hash(raw.as_ref(), &self.counter.to_be_bytes())?;
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

    fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }

    fn set_recovery_codes(&mut self, recovery_codes: Vec<String>) {
        self.recovery_codes = recovery_codes;
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
