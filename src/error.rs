use serde::{Deserialize, Serialize};

/// Error type for the library
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Error {
    /// Invalid key
    ///
    /// if the key type is totp or hotp the the key should be base32 encoded
    InvalidKey,
    /// Invalid digits
    ///
    /// if the digits is not 6, 7 or 8 for hotp or totp
    ///
    /// if the digits is not 5 for steam
    InvalidDigits,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::InvalidDigits => write!(f, "Invalid digits"),
        }
    }
}
