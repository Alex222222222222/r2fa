use std::{fmt::Display, rc::Rc};

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

    fn get_algorithm(&self) -> ring::hmac::Algorithm {
        match self {
            HMACType::SHA1 => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            HMACType::SHA256 => ring::hmac::HMAC_SHA256,
            HMACType::SHA512 => ring::hmac::HMAC_SHA512,
        }
    }

    /// get_hash returns the hash of the key and the string
    pub fn get_hash(&self, key: &[u8], s: &[u8]) -> Result<Rc<[u8]>, error::Error> {
        let algorithm = self.get_algorithm();
        let signer = ring::hmac::Key::new(algorithm, key);
        let hmac = ring::hmac::sign(&signer, s);
        let block = hmac.as_ref();

        Ok(Rc::from(block))
    }
}
