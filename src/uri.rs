use std::fmt::Display;
use std::fmt::Formatter;
use std::path::PathBuf;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error;
use crate::HMACType;
use crate::KeyType;

static URI_DATA_REGEX: Lazy<regex::Regex> =
    Lazy::new(|| Regex::new(r"(secret|algorithm|digits|period|counter|issuer)=[^\s&]*").unwrap());

/// the URI struct
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct URI {
    /// name
    pub name: String,
    /// type
    pub key_type: KeyType,
    /// Secret
    pub secret: String,
    /// algorithm
    pub algorithm: HMACType,
    /// digits
    pub digits: u8,
    /// counter
    ///
    /// The counter is only used for HOTP.
    pub counter: Option<u64>,
    /// period
    ///
    /// The time step in seconds. This is only used for TOTP.
    pub period: Option<u64>,
    /// issuer
    pub issuer: Option<String>,
}

impl URI {
    /// Create a new URI from a string
    ///
    /// ```rust
    /// use libr2fa::URI;
    /// use libr2fa::KeyType;
    /// use libr2fa::HMACType;
    ///
    /// let uri = URI::new_from_uri(
    ///     "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=7&counter=7".to_string()
    /// );
    ///
    /// assert_eq!(uri.key_type, KeyType::HOTP);
    /// assert_eq!(uri.issuer, Some("ACME Co".to_string()));
    /// assert_eq!(uri.digits, 7);
    /// assert_eq!(uri.counter, Some(7));
    /// assert_eq!(uri.algorithm, HMACType::SHA256);
    /// assert_eq!(uri.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string());
    /// ```
    pub fn new_from_uri(value: String) -> Self {
        URI::from(value)
    }

    /// Create a new URI from a QR code
    ///
    /// ```rust
    /// use libr2fa::URI;
    /// use libr2fa::KeyType;
    /// use libr2fa::HMACType;
    ///
    /// let uri = URI::from_qr_code("public/uri_qrcode_test.png");
    /// assert!(uri.is_ok());
    /// let uri = uri.unwrap();
    ///
    /// assert_eq!(uri.key_type, KeyType::TOTP);
    /// assert_eq!(uri.issuer, Some("ACME Co".to_string()));
    /// assert_eq!(uri.digits, 7);
    /// assert_eq!(uri.counter, None);
    /// assert_eq!(uri.algorithm, HMACType::SHA256);
    /// assert_eq!(uri.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string());
    /// ```
    pub fn from_qr_code(path: &str) -> Result<Self, error::Error> {
        // test if it is a valid path
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(error::Error::InvalidPath(
                "target path does not exists".to_string(),
            ));
        }
        // if path is not a file
        if path.is_dir() {
            return Err(error::Error::InvalidPath(
                "target path is not a file".to_string(),
            ));
        }

        // read the file
        let img = image::open(path);
        if let Err(e) = img {
            return Err(error::Error::InvalidPath(format!(
                "could not read file: {}",
                e
            )));
        }
        let img = img.unwrap().to_luma8();

        // check https://docs.rs/rqrr/latest/rqrr/
        let mut img = rqrr::PreparedImage::prepare(img);
        let grids = img.detect_grids();
        if grids.is_empty() {
            return Err(error::Error::InvalidPath(
                "could not detect QR code".to_string(),
            ));
        }
        let grid = &grids[0];
        let decoded = grid.decode();
        if let Err(e) = decoded {
            return Err(error::Error::InvalidPath(format!(
                "could not decode QR code: {}",
                e
            )));
        }
        let (_, decoded) = decoded.unwrap();

        Ok(URI::from(decoded))
    }
}

impl Display for URI {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from(self.clone()))
    }
}

/// Convert a URI to a string
///
/// ```rust
/// use libr2fa::URI;
///
/// let uri = URI::new_from_uri(
///     "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=7&counter=7".to_string()
/// );
///
/// assert_eq!(uri.to_string(), "otpauth://hotp/ACME+Co%3Ajohn.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA256&digits=7&counter=7&issuer=ACME+Co");
/// ```
impl From<URI> for String {
    fn from(value: URI) -> Self {
        let mut uri = String::new();

        uri.push_str("otpauth://");
        uri.push_str(value.key_type.to_string().as_str());
        uri.push('/');
        let name = url::form_urlencoded::byte_serialize(value.name.as_bytes()).collect::<String>();
        uri.push_str(&name);

        let mut keys = vec![];
        let secret = format!("secret={}", value.secret);
        keys.push(secret);
        let algorithm = format!(
            "algorithm={}",
            value.algorithm.to_string().to_ascii_uppercase()
        );
        keys.push(algorithm);
        let digits = format!("digits={}", value.digits);
        keys.push(digits);
        if value.counter.is_some() {
            let counter = format!("counter={}", value.counter.unwrap());
            keys.push(counter);
        }
        if value.period.is_some() {
            let period = format!("period={}", value.period.unwrap());
            keys.push(period);
        }
        if value.issuer.is_some() {
            let issuer = url::form_urlencoded::byte_serialize(value.issuer.unwrap().as_bytes())
                .collect::<String>();
            let issuer = format!("issuer={}", issuer);
            keys.push(issuer);
        }

        uri.push('?');
        uri.push_str(keys.join("&").as_str());

        uri
    }
}

impl From<String> for URI {
    fn from(value: String) -> Self {
        URI::from(value.as_str())
    }
}

impl From<&str> for URI {
    fn from(value: &str) -> Self {
        let mut uri = URI::default();

        let key_type = value.replace("otpauth://", "");
        let key_type = key_type.split('/').collect::<Vec<&str>>();
        if key_type.len() < 2 {
            return uri;
        }
        let name = key_type[1];
        let key_type = key_type[0];
        uri.key_type = KeyType::from(key_type);

        let name = if name.get(0..1) == Some("?") {
            "".to_string()
        } else {
            let name = name.split('?').collect::<Vec<&str>>();
            let name = name[0];
            let name: String = url::form_urlencoded::parse(name.as_bytes())
                .map(|(key, val)| [key, val].concat())
                .collect();

            name
        };
        uri.name = name;

        let caps = URI_DATA_REGEX.captures_iter(value);

        #[cfg(test)]
        {
            println!("{}", value);
            println!("{:?}", caps);
        }

        for cap in caps {
            let cap = cap.get(0);
            if cap.is_none() {
                continue;
            }
            let cap = cap.unwrap().as_str();

            let cap = cap.split('=').collect::<Vec<&str>>();
            if cap.len() != 2 {
                continue;
            }

            #[cfg(test)]
            {
                println!("{:?}", cap);
            }

            let key = cap[0];
            let value = cap[1];

            match key {
                "secret" => uri.secret = value.to_string(),
                "algorithm" => uri.algorithm = HMACType::from(value.to_string()),
                "digits" => {
                    let res = value.parse::<u8>();
                    if let Ok(res) = res {
                        uri.digits = res;
                    }
                }
                "period" => {
                    let period = value.parse::<u64>();
                    if let Ok(period) = period {
                        uri.period = Some(period);
                    }
                }
                "counter" => {
                    let counter = value.parse::<u64>();
                    if let Ok(counter) = counter {
                        uri.counter = Some(counter);
                    }
                }
                "issuer" => {
                    let issuer = value.to_string();
                    let issuer: String = url::form_urlencoded::parse(issuer.as_bytes())
                        .map(|(key, val)| [key, val].concat())
                        .collect();

                    uri.issuer = Some(issuer);
                }
                _ => {}
            }
        }

        uri
    }
}
