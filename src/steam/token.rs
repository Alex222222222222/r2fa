use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct TwoFactorSecret([u8; 20]);

impl TwoFactorSecret {
    pub fn new() -> Self {
        Self([0u8; 20])
    }

    /// parse the self data to base32 token
    pub fn to_base32(&self) -> String {
        data_encoding::BASE32.encode(&self.0)
    }

    /// parse the self data type to base64 token
    pub fn to_shared_secret(&self) -> String {
        data_encoding::BASE64.encode(&self.0)
    }

    /// parse the base32 token to self data type
    pub fn from_base32(secret: String) -> Result<Self, crate::error::Error> {
        // ensure!(secret.len() != 0, "unable to parse empty shared secret");
        if secret.is_empty() {
            return Err(crate::error::Error::InvalidKey);
        }
        let res = data_encoding::BASE32.decode(secret.as_bytes());
        if res.is_err() {
            return Err(crate::error::Error::InvalidKey);
        }
        let res = res.unwrap();
        let res: Result<[u8; 20], _> = res.try_into();
        if res.is_err() {
            return Err(crate::error::Error::InvalidKey);
        }
        let res = res.unwrap();

        Ok(Self(res))
    }

    /// parse the base64 token to self data type
    pub fn parse_shared_secret(secret: String) -> Result<Self, crate::error::Error> {
        // ensure!(secret.len() != 0, "unable to parse empty shared secret");
        if secret.is_empty() {
            return Err(crate::error::Error::InvalidKey);
        }
        let res = data_encoding::BASE64.decode(secret.as_bytes());
        if res.is_err() {
            return Err(crate::error::Error::InvalidKey);
        }
        let res = res.unwrap();
        let res: Result<[u8; 20], _> = res.try_into();
        if res.is_err() {
            return Err(crate::error::Error::InvalidKey);
        }
        let res = res.unwrap();

        Ok(Self(res))
    }

    /// Generate a 5 character 2FA code to that can be used to log in to Steam.
    ///
    /// time is unix epoch in second
    pub fn generate_code(&self, time: u64) -> String {
        let steam_guard_code_translations: [u8; 26] = [
            50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84,
            86, 87, 88, 89,
        ];

        // this effectively makes it so that it creates a new code every 30 seconds.
        let time_bytes: [u8; 8] = build_time_bytes(time / 30u64);
        // let hashed_data = hmacsha1::hmac_sha1(self.0.expose_secret(), &time_bytes);
        let hashed_data = ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY;
        let signer = ring::hmac::Key::new(hashed_data, &self.0);
        let hashed_data = ring::hmac::sign(&signer, &time_bytes);
        let hashed_data = hashed_data.as_ref();
        let mut code_array: [u8; 5] = [0; 5];
        let b = (hashed_data[19] & 0xF) as usize;
        let mut code_point: i32 = ((hashed_data[b] & 0x7F) as i32) << 24
            | (hashed_data[b + 1] as i32) << 16
            | (hashed_data[b + 2] as i32) << 8
            | (hashed_data[b + 3] as i32);

        // for i in 0..5 {
        // code_array[i] = steam_guard_code_translations
        // [code_point as usize % steam_guard_code_translations.len()];
        // code_point /= steam_guard_code_translations.len() as i32;
        // }

        code_array[0] = steam_guard_code_translations
            [code_point as usize % steam_guard_code_translations.len()];
        code_point /= steam_guard_code_translations.len() as i32;

        code_array[1] = steam_guard_code_translations
            [code_point as usize % steam_guard_code_translations.len()];
        code_point /= steam_guard_code_translations.len() as i32;

        code_array[2] = steam_guard_code_translations
            [code_point as usize % steam_guard_code_translations.len()];
        code_point /= steam_guard_code_translations.len() as i32;

        code_array[3] = steam_guard_code_translations
            [code_point as usize % steam_guard_code_translations.len()];
        code_point /= steam_guard_code_translations.len() as i32;

        code_array[4] = steam_guard_code_translations
            [code_point as usize % steam_guard_code_translations.len()];

        String::from_utf8(code_array.to_vec()).unwrap()
    }
}

impl Default for TwoFactorSecret {
    fn default() -> Self {
        Self::new()
    }
}

fn build_time_bytes(time: u64) -> [u8; 8] {
    time.to_be_bytes()
}

impl Serialize for TwoFactorSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(data_encoding::BASE64.encode(&self.0).as_str())
    }
}

impl<'de> Deserialize<'de> for TwoFactorSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(TwoFactorSecret::parse_shared_secret(String::deserialize(deserializer)?).unwrap())
    }
}

impl PartialEq for TwoFactorSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// impl Eq for TwoFactorSecret {}
