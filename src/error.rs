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
    #[cfg(feature = "steam")]
    SteamSerdeError(String, String, String),
    /// error in steam return result
    #[cfg(feature = "steam")]
    SteamError(String, String),
    /// steam login error
    #[cfg(feature = "steam")]
    SteamLoginError(SteamLoginError),
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
            #[cfg(feature = "steam")]
            Error::SteamError(s1, s2) => write!(f, "Steam error: {}, {}", s1, s2),
            #[cfg(feature = "steam")]
            Error::SteamLoginError(s2) => write!(f, "Steam login error: {}", s2),
        }
    }
}

#[cfg(feature = "steam")]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum SteamLoginError {
    BadRSA(String),
    BadCredentials,
    NeedCaptcha { captcha_gid: String },
    Need2FA,
    NeedEmail,
    NeedEmailConfirmation,
    NeedSMS,
    TooManyAttempts,
    NetworkFailure(String),
    OtherFailure(String),
}

#[cfg(feature = "steam")]
impl std::fmt::Display for SteamLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SteamLoginError::BadRSA(s) => write!(f, "Bad RSA: {}", s),
            SteamLoginError::BadCredentials => write!(f, "Bad credentials"),
            SteamLoginError::NeedCaptcha { captcha_gid } => {
                write!(f, "Need captcha: {}", captcha_gid)
            }
            SteamLoginError::Need2FA => write!(f, "Need 2FA"),
            SteamLoginError::NeedEmail => write!(f, "Need email"),
            SteamLoginError::NeedSMS => write!(f, "Need SMS"),
            SteamLoginError::NeedEmailConfirmation => write!(f, "Need email confirmation"),
            SteamLoginError::TooManyAttempts => write!(f, "Too many attempts"),
            SteamLoginError::NetworkFailure(s) => write!(f, "Network failure: {}", s),
            SteamLoginError::OtherFailure(s) => write!(f, "Other failure: {}", s),
        }
    }
}
