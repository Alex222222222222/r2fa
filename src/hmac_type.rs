use std::{fmt::Display, rc::Rc};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};

use crate::error;

/// HMACType is the type of the HMAC
/// SHA1 is the default
/// SHA256 is the recommended
/// SHA512 is the most secure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum HMACType {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl Display for HMACType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.get_digest_name())
    }
}

impl From<String> for HMACType {
    fn from(s: String) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => HMACType::SHA1,
            "sha256" => HMACType::SHA256,
            "sha512" => HMACType::SHA512,
            _ => HMACType::default(),
        }
    }
}

impl HMACType {
    fn get_digest_name(&self) -> &'static str {
        match self {
            HMACType::SHA1 => "sha1",
            HMACType::SHA256 => "sha256",
            HMACType::SHA512 => "sha512",
        }
    }

    /// get_hash returns the hash of the key and the string
    pub fn get_hash(&self, key: &[u8], s: &[u8]) -> Result<Rc<[u8]>, error::Error> {
        let result = match self {
            HMACType::SHA1 => {
                let mac = Hmac::<sha1::Sha1>::new_from_slice(key);
                if let Err(_) = mac {
                    return Err(error::Error::InvalidKey);
                }
                let mut mac = mac.unwrap();

                mac.update(s);
                let result = mac.finalize();
                let result: &[u8] = &result.into_bytes();
                Rc::from(result)
            },
            HMACType::SHA256 => {
                let mac = Hmac::<sha2::Sha256>::new_from_slice(key);
                if let Err(_) = mac {
                    return Err(error::Error::InvalidKey);
                }
                let mut mac = mac.unwrap();

                mac.update(s);
                let result = mac.finalize();
                let result: &[u8] = &result.into_bytes();
                Rc::from(result)
            },
            HMACType::SHA512 => {
                let mac = Hmac::<sha2::Sha512>::new_from_slice(key);
                if let Err(_) = mac {
                    return Err(error::Error::InvalidKey);
                }
                let mut mac = mac.unwrap();

                mac.update(s);
                let result = mac.finalize();
                let result: &[u8] = &result.into_bytes();
                Rc::from(result)
            },
        };

        Ok(result)
    }
}
