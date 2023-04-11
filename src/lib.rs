/// rust implementation for HTOP, TOTP and steam guard tow-factor-authentication
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
use serde::{Deserialize, Serialize};

mod error;
mod hmac_type;
mod hotp;
mod totp;
mod uri;

pub use error::Error;
pub use hmac_type::HMACType;
pub use hotp::HOTPKey;
pub use totp::TOTPKey;
pub use uri::URI;

#[cfg(test)]
mod test;

/// KeyType is the type of the key
/// HOTP is the counter based key
/// TOTP is the time based key
/// STEAM is the steam guard key (TODO not implemented yet)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum KeyType {
    HOTP,
    #[default]
    TOTP,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::HOTP => write!(f, "hotp"),
            KeyType::TOTP => write!(f, "totp"),
        }
    }
}

impl From<&str> for KeyType {
    fn from(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "hotp" => KeyType::HOTP,
            "totp" => KeyType::TOTP,
            _ => KeyType::default(),
        }
    }
}

impl From<String> for KeyType {
    fn from(s: String) -> Self {
        KeyType::from(s.as_str())
    }
}

/// Key is the interface for the keys
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
pub trait Key {
    /// get_code returns the code for the key
    ///
    /// if it is HTOP key, it will increment the counter
    fn get_code(&mut self) -> Result<String, error::Error>;

    /// get the name of the key
    ///
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
    /// hotp_key.set_name("test");
    ///
    /// assert_eq!(hotp_key.get_name(), "test")
    /// ```
    fn get_name(&self) -> &str;

    /// get the recovery codes
    ///
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
    /// hotp_key.set_recovery_codes(&["test".to_string()]);
    ///
    /// assert_eq!(hotp_key.get_recovery_codes(), &["test".to_string()])
    ///
    /// ```
    fn get_recovery_codes(&self) -> &[String];

    /// get the type of the key
    fn get_type(&self) -> KeyType;

    /// set the name of the key
    ///
    /// ```rust
    /// use libr2fa::HOTPKey;
    /// use libr2fa::HMACType;
    /// use libr2fa::Key;
    ///
    /// let mut hotp_key = HOTPKey {
    ///     name: "".to_string(),
    ///     key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
    ///     hmac_type: HMACType::SHA1,
    ///     ..Default::default()
    /// };
    ///
    /// hotp_key.set_name("test");
    ///
    /// assert_eq!(hotp_key.get_name(), "test")
    /// ```
    fn set_name(&mut self, name: &str);

    /// set the recovery codes
    ///
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
    /// hotp_key.set_recovery_codes(&["test".to_string()]);
    ///
    /// assert_eq!(hotp_key.get_recovery_codes(), &["test".to_string()])
    ///
    /// ```
    fn set_recovery_codes(&mut self, recovery_codes: &[String]);
}

/// create a new key from the uri string
///
/// ```rust
/// use libr2fa::otpauth_from_uri;
/// use libr2fa::TOTPKey;
/// use libr2fa::HMACType;
/// use libr2fa::Key;
///
/// let totp_key1 = otpauth_from_uri("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=7&period=60");
/// if let Err(err) = totp_key1 {
///     panic!("{}", err);
/// }
/// let mut totp_key1 = totp_key1.unwrap();
///
/// let mut totp_key2 = TOTPKey {
///     name: "ACME Co:john.doe@email.com".to_string(),
///     key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
///     digits: 7,
///     time_step: 60,
///     hmac_type: HMACType::SHA256,
///     issuer: Some("ACME Co".to_string()),
///     ..Default::default()
///     };
///
/// assert_eq!(totp_key1.get_name(), totp_key2.get_name());
/// assert_eq!(totp_key1.get_type(), totp_key2.get_type());
/// assert_eq!(totp_key1.get_code(), totp_key2.get_code());
/// ```
pub fn otpauth_from_uri(uri: &str) -> Result<Box<dyn Key>, Error> {
    let uri_struct = URI::from(uri);

    match uri_struct.key_type {
        KeyType::HOTP => HOTPKey::from_uri_struct(&uri_struct),
        KeyType::TOTP => TOTPKey::from_uri_struct(&uri_struct),
    }
}

/// create a new key from the uri qrcode
///
/// ```rust
/// use libr2fa::otpauth_from_uri_qrcode;
/// use libr2fa::TOTPKey;
/// use libr2fa::HMACType;
/// use libr2fa::Key;
///
/// let totp_key1 = otpauth_from_uri_qrcode("public/uri_qrcode_test.png");
/// if let Err(err) = totp_key1 {
///     panic!("{}", err);
/// }
/// let mut totp_key1 = totp_key1.unwrap();
///
/// let mut totp_key2 = TOTPKey {
///     name: "ACME Co:john.doe@email.com".to_string(),
///     issuer: Some("ACME Co".to_string()),
///     key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
///     digits: 7,
///     time_step: 60,
///     hmac_type: HMACType::SHA256,
///     ..Default::default()
/// };
///
/// assert_eq!(totp_key1.get_name(), totp_key2.get_name());
/// assert_eq!(totp_key1.get_type(), totp_key2.get_type());
/// assert_eq!(totp_key1.get_code(), totp_key2.get_code());
/// ```
#[cfg(feature = "qrcoderead")]
pub fn otpauth_from_uri_qrcode(path: &str) -> Result<Box<dyn Key>, Error> {
    let uri_struct = URI::from_qr_code(path)?;

    match uri_struct.key_type {
        KeyType::HOTP => HOTPKey::from_uri_struct(&uri_struct),
        KeyType::TOTP => TOTPKey::from_uri_struct(&uri_struct),
    }
}

pub trait OptAuthKey {
    /// to uri struct
    fn to_uri_struct(&self) -> URI;

    /// get the uri for the key
    fn get_uri(&self) -> String {
        self.to_uri_struct().to_string()
    }

    /// get issuer
    fn get_issuer(&self) -> Option<&str>;

    /// create the key from the uri struct
    fn from_uri_struct(uri: &URI) -> Result<Box<dyn Key>, Error>;
}
