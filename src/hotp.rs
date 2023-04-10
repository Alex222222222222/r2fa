use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::{error, HMACType, Key};

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
///     name: "".to_string(),
///     key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
///     digits: 6,
///     counter: 0,
///     recovery_codes: Vec::default(),
///     hmac_type: HMACType::SHA1,
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

impl Key for HOTPKey {
    fn get_type(&self) -> crate::KeyType {
        crate::KeyType::HOTP
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_recovery_codes(&self) -> &[String] {
        &self.recovery_codes
    }

    fn get_code(&mut self) -> Result<String, error::Error> {
        let raw = self.decode_key()?;
        self.counter += 1;

        #[cfg(test)]
        {
            self.counter = 5;
            println!("{:?}", raw);
        }

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
}
