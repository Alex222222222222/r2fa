use std::{
    collections::HashMap,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::{
    blocking,
    cookie::CookieStore,
    header::{HeaderMap, HeaderName, HeaderValue, COOKIE, SET_COOKIE},
};
use serde::{Deserialize, Serialize};

use crate::error;

use super::api_response::{
    AddAuthenticatorResponse, FinalizeAddAuthenticatorResponse, LoginResponse, OAuthData,
    PhoneValidateResponse, QueryTimeResponse, RemoveAuthenticatorResponse, SteamApiResponse,
};

static STEAM_COOKIE_URL: once_cell::sync::Lazy<reqwest::Url> =
    once_cell::sync::Lazy::new(|| reqwest::Url::parse("https://steamcommunity.com").unwrap());
static STEAM_API_BASE_URL: once_cell::sync::Lazy<reqwest::Url> =
    once_cell::sync::Lazy::new(|| reqwest::Url::parse("https://api.steampowered.com").unwrap());

const GET_SERVER_TIME_END_POINT: &str = "/ITwoFactorService/QueryTime/v0001";

const GET_SERVER_TIME_ERROR_MESSAGE: &str = "Failed to get server time from Steam";
const GET_SESSION_ERROR_MESSAGE: &str = "Failed to get session from Steam";
const GET_OAUTH_DATA_ERROR_MESSAGE: &str = "Failed to get OAuth data from Steam";
const LOGIN_ERROR_MESSAGE: &str = "Failed to login to Steam";
const TRANSFER_LOGIN_ERROR_MESSAGE: &str = "Failed to transfer login to Steam";
const PHONEAJAX_ERROR_MESSAGE: &str = "Failed to get phone ajax from Steam";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub steam_login: String,
    pub steam_login_secure: String,
    pub web_cookie: Option<String>,
    pub token: String,
    pub steam_id: u64,
}

/// Queries Steam for the current time.
///
/// Endpoint: `/ITwoFactorService/QueryTime/v0001`
///
/// Example Response:
/// ```json
/// {
///   "response": {
///     "server_time": "1655768666",
///     "skew_tolerance_seconds": "60",
///     "large_time_jink": "86400",
///     "probe_frequency_seconds": 3600,
///     "adjusted_time_probe_frequency_seconds": 300,
///     "hint_probe_frequency_seconds": 60,
///     "sync_timeout": 60,
///     "try_again_seconds": 900,
///     "max_attempts": 3
///   }
/// }
/// ```
pub fn get_server_time() -> Result<QueryTimeResponse, error::Error> {
    let client = reqwest::blocking::Client::new();

    let url = STEAM_API_BASE_URL.join(GET_SERVER_TIME_END_POINT).unwrap();

    let resp = client.post(url).body("steamid=0").send();
    if let Err(e) = resp {
        return Err(error::Error::ReqwestError(
            GET_SERVER_TIME_ERROR_MESSAGE.to_string(),
            e.to_string(),
        ));
    }
    let resp = resp.unwrap().json::<SteamApiResponse<QueryTimeResponse>>();
    if let Err(e) = resp {
        return Err(error::Error::ReqwestError(
            GET_SERVER_TIME_ERROR_MESSAGE.to_string(),
            e.to_string(),
        ));
    }

    Ok(resp.unwrap().response)
}

/// Provides raw access to the Steam API. Handles cookies, some de serialization, etc. to make it easier. It covers `ITwoFactorService` from the Steam web API, and some mobile app specific api endpoints.
#[derive(Debug)]
pub struct SteamApiClient {
    cookies: reqwest::cookie::Jar,
    client: reqwest::blocking::Client,
    pub session: Option<Session>,
}

impl SteamApiClient {
    pub fn new(session: Option<Session>) -> SteamApiClient {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("X-Requested-With")
                .expect("could not build default request headers"),
            HeaderValue::from_str("com.valvesoftware.android.steam.community")
                .expect("could not build default request headers"),
        );

        SteamApiClient {
			cookies: reqwest::cookie::Jar::default(),
			client: reqwest::blocking::ClientBuilder::new()
				.cookie_store(true)
				.user_agent("Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
				.default_headers(headers)
				.build()
				.unwrap(),
			session,
		}
    }

    fn build_session(&self, data: &OAuthData) -> Session {
        return Session {
            token: data.oauth_token.clone(),
            steam_id: data.steamid.parse().unwrap(),
            steam_login: format!("{}%7C%7C{}", data.steamid, data.wgtoken),
            steam_login_secure: format!("{}%7C%7C{}", data.steamid, data.wgtoken_secure),
            session_id: self
                .extract_session_id()
                .expect("failed to extract session id from cookies"),
            web_cookie: Some(data.webcookie.clone()),
        };
    }

    fn extract_session_id(&self) -> Option<String> {
        let cookies = self.cookies.cookies(&STEAM_COOKIE_URL).unwrap();
        let cookies = cookies.to_str().unwrap();
        for cookie in cookies.split(";") {
            let cookie = cookie.trim();
            let cookie = cookie.split("=");
            let cookie = cookie.collect::<Vec<&str>>();
            if cookie[0] == "sessionid" {
                return Some(cookie[1].into());
            }
        }
        return None;
    }

    pub fn save_cookies_from_response(&mut self, response: &reqwest::blocking::Response) {
        let set_cookie_iter = response.headers().get_all(SET_COOKIE);

        for c in set_cookie_iter {
            c.to_str()
                .into_iter()
                .for_each(|cookie_str| self.cookies.add_cookie_str(cookie_str, &STEAM_COOKIE_URL));
        }
    }

    pub fn request<U: reqwest::IntoUrl + std::fmt::Display>(
        &self,
        method: reqwest::Method,
        url: U,
    ) -> blocking::RequestBuilder {
        self.cookies
            .add_cookie_str("mobileClientVersion=0 (2.1.3)", &STEAM_COOKIE_URL);
        self.cookies
            .add_cookie_str("mobileClient=android", &STEAM_COOKIE_URL);
        self.cookies
            .add_cookie_str("Steam_Language=english", &STEAM_COOKIE_URL);
        if let Some(session) = &self.session {
            self.cookies.add_cookie_str(
                format!("sessionid={}", session.session_id).as_str(),
                &STEAM_COOKIE_URL,
            );
        }

        self.client
            .request(method, url)
            .header(COOKIE, self.cookies.cookies(&STEAM_COOKIE_URL).unwrap())
    }

    pub fn get<U: reqwest::IntoUrl + std::fmt::Display>(&self, url: U) -> blocking::RequestBuilder {
        self.request(reqwest::Method::GET, url)
    }

    pub fn post<U: reqwest::IntoUrl + std::fmt::Display>(
        &self,
        url: U,
    ) -> blocking::RequestBuilder {
        self.request(reqwest::Method::POST, url)
    }

    /// Updates the cookie jar with the session cookies by pinging steam servers.
    #[warn(unused_must_use)]
    pub fn update_session(&mut self) -> Result<(), error::Error> {
        // TODO change this url
        let resp = self
			.get("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client".parse::<reqwest::Url>().unwrap())
			.send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                GET_SESSION_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        }
        let resp = resp.unwrap();

        self.save_cookies_from_response(&resp);

        Ok(())
    }

    /// Endpoint: POST /login/dologin
    pub fn login(
        &mut self,
        username: String,
        encrypted_password: String,
        two_factor_code: String,
        email_code: String,
        captcha_gid: String,
        captcha_text: String,
        rsa_timestamp: String,
    ) -> Result<LoginResponse, error::Error> {
        let mut params: HashMap<String, String> = HashMap::new();
        params.insert(
            "donotcache".into(),
            format!(
                "{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    * 1000
            ),
        );
        params.insert("username".into(), username);
        params.insert("password".into(), encrypted_password);
        params.insert("twofactorcode".into(), two_factor_code);
        params.insert("emailauth".into(), email_code);
        params.insert("captchagid".into(), captcha_gid);
        params.insert("captcha_text".into(), captcha_text);
        params.insert("rsatimestamp".into(), rsa_timestamp);
        params.insert("remember_login".into(), "true".into());
        params.insert("oauth_client_id".into(), "DE45CD61".into());
        params.insert(
            "oauth_scope".into(),
            "read_profile write_profile read_client write_client".into(),
        );

        // TODO change this
        let resp = self
            .post("https://steamcommunity.com/login/dologin")
            .form(&params)
            .send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                LOGIN_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        }
        let resp = resp.unwrap();
        self.save_cookies_from_response(&resp);
        let text = resp.text();
        if let Err(e) = text {
            return Err(error::Error::ReqwestError(
                LOGIN_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        }
        let text = text.unwrap();

        let login_resp: Result<LoginResponse, serde_json::Error> =
            serde_json::from_str(text.as_str());
        if let Err(e) = login_resp {
            return Err(error::Error::SteamSerdeError(
                LOGIN_ERROR_MESSAGE.to_string(),
                text.to_string(),
                e.to_string(),
            ));
        };

        // TODO delete this 
        println!("{}", text);

        let login_resp = login_resp.unwrap();

        if let Some(oauth) = &login_resp.oauth {
            self.session = Some(self.build_session(&oauth));
        }

        return Ok(login_resp);
    }

    /// A secondary step in the login flow. Does not seem to always be needed?
    /// Endpoints: provided by `login()`
    pub fn transfer_login(&mut self, login_resp: LoginResponse) -> Result<OAuthData, error::Error> {
        match (login_resp.transfer_urls, login_resp.transfer_parameters) {
            (Some(urls), Some(params)) => {
                for url in urls {
                    let resp = self.client.post(url).json(&params).send();
                    if let Err(e) = resp {
                        return Err(error::Error::ReqwestError(
                            TRANSFER_LOGIN_ERROR_MESSAGE.to_string(),
                            e.to_string(),
                        ));
                    };
                    let resp = resp.unwrap();
                    self.save_cookies_from_response(&resp);
                }

                let oauth = OAuthData {
                    oauth_token: params.auth,
                    steamid: params.steamid.parse().unwrap(),
                    wgtoken: params.token_secure.clone(), // guessing
                    wgtoken_secure: params.token_secure,
                    webcookie: params.webcookie,
                };
                self.session = Some(self.build_session(&oauth));
                return Ok(oauth);
            }
            (None, None) => {
                return Err(error::Error::SteamError(
                    TRANSFER_LOGIN_ERROR_MESSAGE.to_string(),
                    "did not receive transfer_parameters or transfer_urls".to_string(),
                ));
            }
            (_, None) => {
                return Err(error::Error::SteamError(
                    TRANSFER_LOGIN_ERROR_MESSAGE.to_string(),
                    "did not receive transfer_parameters".to_string(),
                ));
            }
            (None, _) => {
                Err(error::Error::SteamError(
                    TRANSFER_LOGIN_ERROR_MESSAGE.to_string(),
                    "did not receive transfer_urls".to_string(),
                ))
            }
        }
    }

    /// Likely removed now
    ///
    /// One of the endpoints that handles phone number things. Can check to see if phone is present on account, and maybe do some other stuff. It's not really super clear.
    ///
    /// Host: steamcommunity.com
    /// Endpoint: POST /steamguard/phoneajax
    /// Requires `sessionid` cookie to be set.
    fn phoneajax(&self, op: &str, arg: &str) -> Result<bool, error::Error> {
        let mut params = HashMap::new();
        params.insert("op", op);
        params.insert("arg", arg);
        params.insert(
            "sessionid",
            self.session.as_ref().unwrap().session_id.as_str(),
        );

        if op == "check_sms_code" {
            params.insert("checkfortos", "0");
            params.insert("skipvoip", "1");
        }

        // TODO change this
        let resp = self
            .post("https://steamcommunity.com/steamguard/phoneajax")
            .form(&params)
            .send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        let body = resp.text();
        if let Err(e) = body {
            return Err(error::Error::ReqwestError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        };
        let body = body.unwrap();

        let result = serde_json::from_str::<serde_json::Value>(body.as_str());
        if let Err(e) = result {
            return Err(error::Error::SteamSerdeError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                body,
                e.to_string(),
            ));
        };
        let result = result.unwrap();

        if result["has_phone"] != serde_json::Value::Null {
            let res = result["has_phone"].as_bool();
            if res.is_none() {
                return Err(error::Error::SteamError(
                    PHONEAJAX_ERROR_MESSAGE.to_string(),
                    "failed to parse has_phone field into boolean".to_string(),
                ));
            }
            Ok(res.unwrap())
        } else if result["success"] != serde_json::Value::Null {
            let res = result["success"].as_bool();
            if res.is_none() {
                return Err(error::Error::SteamError(
                    PHONEAJAX_ERROR_MESSAGE.to_string(),
                    "failed to parse success field into boolean".to_string(),
                ));
            }
            return Ok(res.unwrap());
        } else {
            return Ok(false);
        }
    }

    /// Works similar to phoneajax. Used in the process to add a phone number to a steam account.
    /// Valid ops:
    /// - get_phone_number => `input` is treated as a phone number to add to the account. Yes, this is somewhat counter intuitive.
    /// - resend_sms
    /// - get_sms_code => `input` is treated as a the SMS code that was texted to the phone number. Again, this is somewhat counter intuitive. After this succeeds, the phone number is added to the account.
    /// - email_verification => If the account is protected with steam guard email, a verification link is sent. After the link in the email is clicked, send this op. After, an SMS code is sent to the phone number.
    /// - retry_email_verification
    ///
    /// Host: store.steampowered.com
    /// Endpoint: /phone/add_ajaxop
    fn phone_add_ajaxop(&self, op: &str, input: &str) -> Result<String, error::Error> {
        let mut params = HashMap::new();
        params.insert("op", op);
        params.insert("input", input);
        params.insert(
            "sessionid",
            self.session.as_ref().unwrap().session_id.as_str(),
        );

        // TODO change this
        let resp = self
            .post("https://store.steampowered.com/phone/add_ajaxop")
            .form(&params)
            .send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        let text = resp.text();
        if let Err(e) = text {
            return Err(error::Error::ReqwestError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        };

        // TODO check the result of the text
        Ok(text.unwrap())
    }

    pub fn has_phone(&self) -> Result<bool, error::Error> {
        return self.phoneajax("has_phone", "null");
    }

    pub fn check_sms_code(&self, sms_code: String) -> Result<bool, error::Error> {
        return self.phoneajax("check_sms_code", sms_code.as_str());
    }

    pub fn check_email_confirmation(&self) -> Result<bool, error::Error> {
        return self.phoneajax("email_confirmation", "");
    }

    pub fn add_phone_number(&self, phone_number: String) -> Result<bool, error::Error> {
        // TODO
        return self.phoneajax("add_phone_number", phone_number.as_str());
    }

    /// Provides lots of juicy information, like if the number is a VOIP number.
    /// Host: store.steampowered.com
    /// Endpoint: POST /phone/validate
    /// Body format: form data
    /// Example:
    /// ```form
    /// sessionID=FOO&phoneNumber=%2B1+1234567890
    /// ```
    /// Found on page: https://store.steampowered.com/phone/add
    pub fn phone_validate(
        &self,
        phone_number: &String,
    ) -> Result<PhoneValidateResponse, error::Error> {
        let mut params = HashMap::new();
        params.insert(
            "sessionID",
            self.session.as_ref().unwrap().session_id.as_str(),
        );
        params.insert("phoneNumber", phone_number.as_str());

        let resp = self
            .client
            .post("https://store.steampowered.com/phone/validate")
            .form(&params)
            .send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        let body = resp.text();
        if let Err(e) = body {
            return Err(error::Error::ReqwestError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                e.to_string(),
            ));
        };
        let body = body.unwrap();

        let res = serde_json::from_str::<SteamApiResponse<PhoneValidateResponse>>(body.as_str());
        if let Err(e) = res {
            return Err(error::Error::SteamSerdeError(
                PHONEAJAX_ERROR_MESSAGE.to_string(),
                body,
                e.to_string(),
            ));
        };
        let res = res.unwrap();

        Ok(res.response)
    }

    /// Starts the authenticator linking process.
    /// This doesn't check any prereqisites to ensure the request will pass validation on Steam's side (eg. sms/email confirmations).
    /// A valid `Session` is required for this request. Cookies are not needed for this request, but they are set anyway.
    ///
    /// Host: api.steampowered.com
    /// Endpoint: POST /ITwoFactorService/AddAuthenticator/v0001
    pub fn add_authenticator(
        &mut self,
        device_id: String,
    ) -> Result<AddAuthenticatorResponse, error::Error> {
        // test if the session is valid
        if self.session.is_none() {
            return Err(error::Error::SteamError(
                "add_authenticator".to_string(),
                "session is none".to_string(),
            ));
        }

        let mut params = HashMap::new();
        params.insert("access_token", self.session.as_ref().unwrap().token.clone());
        params.insert(
            "steamid",
            self.session.as_ref().unwrap().steam_id.to_string(),
        );
        params.insert("authenticator_type", "1".into());
        params.insert("device_identifier", device_id);
        params.insert("sms_phone_id", "1".into());

        // TODO change this
        let resp = self
            .post(format!(
                "{}/ITwoFactorService/AddAuthenticator/v0001",
                STEAM_API_BASE_URL.to_string()
            ))
            .form(&params)
            .send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                "add_authenticator".to_string(),
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        // TODO change this
        self.save_cookies_from_response(&resp);
        let text = resp.text();
        if let Err(e) = text {
            return Err(error::Error::ReqwestError(
                "add_authenticator".to_string(),
                e.to_string(),
            ));
        };
        let text = text.unwrap();

        let resp =
            serde_json::from_str::<SteamApiResponse<AddAuthenticatorResponse>>(text.as_str());
        if let Err(e) = resp {
            return Err(error::Error::SteamSerdeError(
                "add_authenticator".to_string(),
                text,
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        Ok(resp.response)
    }

    /// Host: api.steampowered.com
    /// Endpoint: POST /ITwoFactorService/FinalizeAddAuthenticator/v0001
    pub fn finalize_authenticator(
        &self,
        sms_code: String,
        code_2fa: String,
        time_2fa: u64,
    ) -> Result<FinalizeAddAuthenticatorResponse, error::Error> {
        // test if the session is valid
        if self.session.is_none() {
            return Err(error::Error::SteamError(
                "add_authenticator".to_string(),
                "session is none".to_string(),
            ));
        }

        let mut params = HashMap::new();
        params.insert("access_token", self.session.as_ref().unwrap().token.clone());
        params.insert(
            "steamid",
            self.session.as_ref().unwrap().steam_id.to_string(),
        );
        params.insert("activation_code", sms_code);
        params.insert("authenticator_code", code_2fa);
        params.insert("authenticator_time", time_2fa.to_string());

        // TODO change this
        let resp = self
            .post(format!(
                "{}/ITwoFactorService/FinalizeAddAuthenticator/v0001",
                STEAM_API_BASE_URL.to_string()
            ))
            .form(&params)
            .send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                "add_authenticator".to_string(),
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        // TODO change this
        let text = resp.text();
        if let Err(e) = text {
            return Err(error::Error::ReqwestError(
                "add_authenticator".to_string(),
                e.to_string(),
            ));
        };
        let text = text.unwrap();

        let resp = serde_json::from_str::<SteamApiResponse<FinalizeAddAuthenticatorResponse>>(
            text.as_str(),
        );
        if let Err(e) = resp {
            return Err(error::Error::SteamSerdeError(
                "add_authenticator".to_string(),
                text,
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        Ok(resp.response)
    }

    /// Host: api.steampowered.com
    /// Endpoint: POST /ITwoFactorService/RemoveAuthenticator/v0001
    pub fn remove_authenticator(
        &self,
        revocation_code: String,
    ) -> Result<RemoveAuthenticatorResponse, error::Error> {
        let mut params = HashMap::new();
        params.insert("access_token", self.session.as_ref().unwrap().token.clone());
        params.insert(
            "steamid",
            self.session.as_ref().unwrap().steam_id.to_string(),
        );
        params.insert("revocation_code", revocation_code);
        params.insert("steamguard_scheme", "2".into());

        // TODO change this
        let resp = self
            .post(format!(
                "{}/ITwoFactorService/RemoveAuthenticator/v0001",
                STEAM_API_BASE_URL.to_string()
            ))
            .form(&params)
            .send();
        if let Err(e) = resp {
            return Err(error::Error::ReqwestError(
                "remove_authenticator".to_string(),
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        let text = resp.text();
        if let Err(e) = text {
            return Err(error::Error::ReqwestError(
                "remove_authenticator".to_string(),
                e.to_string(),
            ));
        };
        let text = text.unwrap();

        // TODO change this
        let resp =
            serde_json::from_str::<SteamApiResponse<RemoveAuthenticatorResponse>>(text.as_str());
        if let Err(e) = resp {
            return Err(error::Error::SteamSerdeError(
                "remove_authenticator".to_string(),
                text,
                e.to_string(),
            ));
        };
        let resp = resp.unwrap();

        Ok(resp.response)
    }
}
