/// rust implementation for HTOP, TOTP and steam guard tow-factor-authentication
///
/// usage:
/// ```rust
/// use libr2fa::HOTPKey
/// use libr2fa::HMACType
///
/// let mut hotp_key = HOTPKey {
///     name: "".to_string(),
///     key: "your base32 encoded key".to_string(),
///     digits: 6,
///     counter: 0,
///     recovery_codes: Vec::default(),
///     hmac_type: HMACType::SHA1,
/// };
///
/// let code = hotp_key.get_code().unwrap();
/// ```
use std::{fmt::Display, rc::Rc};

use serde::{Deserialize, Serialize};

pub mod error;
pub mod hotp;
pub mod totp;

pub use error::Error;
pub use hotp::HOTPKey;

#[cfg(test)]
mod test;

/// KeyType is the type of the key
/// HOTP is the counter based key
/// TOTP is the time based key
/// STEAM is the steam guard key (TODO not implemented yet)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    HOTP,
    TOTP,
}

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
    fn get_hash(&self, key: &[u8], s: &[u8]) -> Result<Rc<[u8]>, error::Error> {
        let algorithm = self.get_algorithm();
        let signer = ring::hmac::Key::new(algorithm, key);
        let hmac = ring::hmac::sign(&signer, s);
        let block = hmac.as_ref();

        Ok(Rc::from(block))
    }
}

/// Key is the interface for the keys
///
/// usage:
/// ```rust
/// use libr2fa::HOTPKey
/// use libr2fa::HMACType
///
/// let mut hotp_key = HOTPKey {
///     name: "".to_string(),
///     key: "your base32 encoded key".to_string(),
///     digits: 6,
///     counter: 0,
///     recovery_codes: Vec::default(),
///     hmac_type: HMACType::SHA1,
/// };
///
/// let code = hotp_key.get_code().unwrap();
/// ```
pub trait Key {
    /// get_code returns the code for the key
    ///
    /// if it is HTOP key, it will increment the counter
    fn get_code(&mut self) -> Result<String, error::Error>;

    /// get the name of the key
    fn get_name(&self) -> &str;

    /// get the recovery codes
    fn get_recovery_codes(&self) -> &[String];

    /// get the type of the key
    fn get_type(&self) -> KeyType;
}
