use crate::{Error, Key, OtpAuthKey};

use super::{token::TwoFactorSecret, MaFile};

/// the steam key struct
///
/// ```rust
/// use libr2fa::SteamKey;
/// use libr2fa::Key;
/// use libr2fa::steam::MaFile;
///
/// let mafile = MaFile::from_file("./public/mafile_test.mafile");
///
/// assert!(mafile.is_ok());
///
/// let steam_key = SteamKey::from_mafile(mafile.unwrap());
///
/// assert!(steam_key.is_ok());
///
/// let mut steam_key = steam_key.unwrap();
///
/// let code = steam_key.get_code();
///
/// assert!(code.is_ok());
///
/// let code = code.unwrap();
///
/// println!("steam code: {}", code);
/// ```
pub struct SteamKey {
    pub token: TwoFactorSecret,
    pub mafile: MaFile,
}

impl SteamKey {
    pub fn from_mafile(mafile: MaFile) -> Result<Self, Error> {
        let token = TwoFactorSecret::parse_shared_secret(mafile.shared_secret.clone())?;

        Ok(SteamKey { token, mafile })
    }
}

impl Key for SteamKey {
    fn get_code(&mut self) -> Result<String, crate::error::Error> {
        // get unix epoch in seconds
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let res = self.token.generate_code(time);

        Ok(res)
    }

    fn get_name(&self) -> &str {
        &self.mafile.account_name
    }

    fn get_recovery_codes(&self) -> Vec<String> {
        let code = self.mafile.revocation_code.clone();

        vec![code]
    }

    fn get_type(&self) -> crate::KeyType {
        crate::KeyType::Steam
    }

    fn set_name(&mut self, name: &str) {
        self.mafile.account_name = name.to_string();
    }

    fn set_recovery_codes(&mut self, recovery_codes: Vec<String>) {
        if recovery_codes.is_empty() {
            return;
        }
        self.mafile.revocation_code = recovery_codes[0].clone();
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl OtpAuthKey for SteamKey {
    fn to_uri_struct(&self) -> crate::URI {
        crate::URI {
            name: self.mafile.account_name.clone(),
            key_type: crate::KeyType::Steam,
            secret: self.token.to_base32(),
            algorithm: None,
            digits: None,
            counter: None,
            period: None,
            issuer: Some(String::from("Steam")),
        }
    }

    fn get_issuer(&self) -> Option<&str> {
        Some("Steam")
    }

    fn from_uri_struct(uri: &crate::URI) -> Result<Box<dyn Key>, crate::Error> {
        let mafile = MaFile {
            account_name: uri.name.clone(),
            device_id: "".to_string(),
            identity_secret: "".to_string(),
            revocation_code: "".to_string(),
            secret_1: "".to_string(),
            serial_number: 0,
            server_time: 0,
            shared_secret: (TwoFactorSecret::from_base32(uri.secret.clone())?).to_shared_secret(),
            status: 0,
            token_gid: "".to_string(),
            uri: uri.to_string(),
        };

        let steam_key = SteamKey {
            token: TwoFactorSecret::from_base32(uri.secret.clone())?,
            mafile,
        };

        Ok(Box::from(steam_key))
    }
}
