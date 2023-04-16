// impl std::error::Error for LoginError {}
//
// impl From<reqwest::Error> for LoginError {
// fn from(err: reqwest::Error) -> Self {
// LoginError::NetworkFailure(err)
// }
// }
//
// impl From<anyhow::Error> for LoginError {
// fn from(err: anyhow::Error) -> Self {
// LoginError::OtherFailure(err)
// }
// }

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use rsa::{PublicKey, RsaPublicKey};

use crate::{error, steam::api_response::RsaResponse};

use super::{
    api_response::LoginResponse,
    steam_api::{LoginParams, SteamApiClient},
};

/// Handles the user login flow.
#[derive(Debug)]
pub struct UserLogin {
    pub username: String,
    pub password: String,
    pub captcha_required: bool,
    pub captcha_gid: String,
    pub captcha_text: String,
    pub two_factor_code: String,
    pub email_code: String,
    pub steam_id: u64,

    client: SteamApiClient,
}

impl UserLogin {
    pub fn new(username: String, password: String) -> UserLogin {
        UserLogin {
            username,
            password,
            captcha_required: false,
            captcha_gid: String::from("-1"),
            captcha_text: String::from(""),
            two_factor_code: String::from(""),
            email_code: String::from(""),
            steam_id: 0,
            client: SteamApiClient::new(None),
        }
    }

    pub fn login(&mut self) -> Result<super::steam_api::Session, error::Error> {
        if self.captcha_required && self.captcha_text.is_empty() {
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::NeedCaptcha {
                    captcha_gid: self.captcha_gid.clone(),
                },
            ));
        }

        if self.client.session.is_none() {
            self.client.update_session()?;
        }

        let mut params = HashMap::new();
        params.insert(
            "donotcache",
            format!(
                "{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    * 1000
            ),
        );
        params.insert("username", self.username.clone());

        let resp = self
            .client
            .post("https://steamcommunity.com/login/getrsakey")
            .form(&params)
            .send();
        if let Err(error) = resp {
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::BadRSA(error.to_string()),
            ));
        }
        let resp = resp.unwrap();

        let body = resp.text().unwrap();
        let res = serde_json::from_str::<RsaResponse>(&body);
        if let Err(error) = res {
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::BadRSA(format!(
                    "Failed to parse RSA response: {}, {}",
                    body, error,
                )),
            ));
        }
        let rsa_resp = res.unwrap();
        let rsa_timestamp = rsa_resp.timestamp.clone();
        let encrypted_password = encrypt_password(rsa_resp, &self.password);

        let login_params = LoginParams {
            username: self.username.clone(),
            encrypted_password,
            two_factor_code: self.two_factor_code.clone(),
            email_code: self.email_code.clone(),
            captcha_gid: self.captcha_gid.clone(),
            captcha_text: self.captcha_text.clone(),
            rsa_timestamp,
        };

        let login_resp: LoginResponse = self.client.login(&login_params)?;

        if login_resp.message.contains("too many login") {
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::TooManyAttempts,
            ));
        }

        if login_resp.message.contains("Incorrect login") {
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::BadCredentials,
            ));
        }

        if login_resp.captcha_needed {
            self.captcha_gid = login_resp.captcha_gid;
            self.captcha_required = true;
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::NeedCaptcha {
                    captcha_gid: self.captcha_gid.clone(),
                },
            ));
        }

        if login_resp.email_auth_needed {
            self.steam_id = login_resp.email_steam_id;
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::NeedEmail,
            ));
        }

        if login_resp.requires_two_factor {
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::Need2FA,
            ));
        }

        if !login_resp.login_complete {
            return Err(error::Error::SteamLoginError(
                error::SteamLoginError::BadCredentials,
            ));
        }

        if login_resp.needs_transfer_login() {
            self.client.transfer_login(login_resp)?;
        }

        Ok(self.client.session.as_ref().unwrap().to_owned())
    }
}

fn encrypt_password(rsa_resp: RsaResponse, password: &String) -> String {
    let rsa_exponent = rsa::BigUint::parse_bytes(rsa_resp.public_key_exp.as_bytes(), 16).unwrap();
    let rsa_modulus = rsa::BigUint::parse_bytes(rsa_resp.public_key_mod.as_bytes(), 16).unwrap();
    let public_key = RsaPublicKey::new(rsa_modulus, rsa_exponent).unwrap();

    let encrypt_password = public_key
        .encrypt(
            &mut rand::rngs::OsRng,
            rsa::Pkcs1v15Encrypt,
            password.as_bytes(),
        )
        .unwrap();

    data_encoding::BASE64.encode(&encrypt_password)
}
