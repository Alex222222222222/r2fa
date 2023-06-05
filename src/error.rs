use serde::{Deserialize, Serialize};

/// Error type for the library
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
    /// invalid uri string
    ///
    /// with a description of the error
    InvalidURI(String),
    /// invalid file path
    InvalidPath(String),
    /// reqwest error, with when the error happen and a description of the error
    #[cfg(feature = "steam")]
    ReqwestError(String, String),
    /// error in serde in steam module
    ///
    /// the first string is the error message
    ///
    /// the second string is the string tring to be parsed
    ///
    /// the third string is the serde error
    #[cfg(feature = "steam")]
    SteamSerdeError(String, String, String),
    /// io error
    ///
    /// the first string is the error message
    ///
    /// the second string is the path
    ///
    /// the third string is the io error
    IOError(String, String, String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::InvalidDigits => write!(f, "Invalid digits"),
            Error::InvalidURI(s) => write!(f, "Invalid URI: {}", s),
            Error::InvalidPath(s) => write!(f, "Invalid path: {}", s),
            #[cfg(feature = "steam")]
            Error::ReqwestError(s1, s2) => write!(f, "Reqwest error: {}, {}", s1, s2),
            #[cfg(feature = "steam")]
            Error::SteamSerdeError(s1, s2, s3) => {
                write!(f, "Steam serde error: {}, {}, {}", s1, s2, s3)
            }
            Error::IOError(s1, s2, s3) => write!(f, "IO error: {}, {}, {}", s1, s2, s3),
        }
    }
}
