use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginTransferParameters {
    pub steamid: String,
    pub token_secure: String,
    pub auth: String,
    pub remember_login: bool,
    pub webcookie: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthData {
    pub oauth_token: String,
    pub steamid: String,
    pub wgtoken: String,
    pub wgtoken_secure: String,
    #[serde(default)]
    pub webcookie: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RsaResponse {
    pub success: bool,
    #[serde(rename = "publickey_exp")]
    pub public_key_exp: String,
    #[serde(rename = "publickey_mod")]
    pub public_key_mod: String,
    pub timestamp: String,
    pub token_gid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    #[serde(default)]
    pub login_complete: bool,
    #[serde(default)]
    pub captcha_needed: bool,
    #[serde(default)]
    pub captcha_gid: String,
    #[serde(
        default,
        rename = "emailsteamid",
        deserialize_with = "super::super::utils::deserialize_u64_from_string"
    )]
    pub email_steam_id: u64,
    #[serde(default, rename = "emailauth_needed")]
    pub email_auth_needed: bool,
    #[serde(default, rename = "requires_twofactor")]
    pub requires_two_factor: bool,
    #[serde(default)]
    pub message: String,
    #[serde(default, deserialize_with = "deserialize_option_oauth_data")]
    pub oauth: Option<OAuthData>,
    pub transfer_urls: Option<Vec<String>>,
    pub transfer_parameters: Option<LoginTransferParameters>,
}

impl LoginResponse {
    pub fn needs_transfer_login(&self) -> bool {
        self.transfer_urls.is_some() || self.transfer_parameters.is_some()
    }
}

fn deserialize_option_oauth_data<'de, D>(deserializer: D) -> Result<Option<OAuthData>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let data: OAuthData = serde_json::from_str(s.as_str()).map_err(serde::de::Error::custom)?;
    Ok(Some(data))
}

// #[cfg(test)]
// mod test {
// use super::*;
//
// #[test]
// fn test_oauth_data_parse() {
// This example is from a login response that did not contain any transfer URLs.
// let oauth: OAuthData = serde_json::from_str("{\"steamid\":\"78562647129469312\",\"account_name\":\"feuarus\",\"oauth_token\":\"fd2fdb3d0717bcd2220d98c7ec61c7bd\",\"wgtoken\":\"72E7013D598A4F68C7E268F6FA3767D89D763732\",\"wgtoken_secure\":\"21061EA13C36D7C29812CAED900A215171AD13A2\",\"webcookie\":\"6298070A226E5DAD49938D78BCF36F7A7118FDD5\"}").unwrap();
//
// assert_eq!(oauth.steamid, "78562647129469312");
// assert_eq!(oauth.oauth_token, "fd2fdb3d0717bcd2220d98c7ec61c7bd");
// assert_eq!(oauth.wgtoken, "72E7013D598A4F68C7E268F6FA3767D89D763732");
// assert_eq!(
// oauth.wgtoken_secure,
// "21061EA13C36D7C29812CAED900A215171AD13A2"
// );
// assert_eq!(oauth.webcookie, "6298070A226E5DAD49938D78BCF36F7A7118FDD5");
// }
//
// #[test]
// fn test_login_response_parse() {
// let result = serde_json::from_str::<LoginResponse>(include_str!(
// "../fixtures/api-responses/login-response1.json"
// ));
//
// assert!(
// matches!(result, Ok(_)),
// "got error: {}",
// result.unwrap_err()
// );
// let resp = result.unwrap();
//
// let oauth = resp.oauth.unwrap();
// assert_eq!(oauth.steamid, "78562647129469312");
// assert_eq!(oauth.oauth_token, "fd2fdb3d0717bad2220d98c7ec61c7bd");
// assert_eq!(oauth.wgtoken, "72E7013D598A4F68C7E268F6FA3767D89D763732");
// assert_eq!(
// oauth.wgtoken_secure,
// "21061EA13C36D7C29812CAED900A215171AD13A2"
// );
// assert_eq!(oauth.webcookie, "6298070A226E5DAD49938D78BCF36F7A7118FDD5");
// }
//
// #[test]
// fn test_login_response_parse_missing_webcookie() {
// let result = serde_json::from_str::<LoginResponse>(include_str!(
// "../fixtures/api-responses/login-response-missing-webcookie.json"
// ));
//
// assert!(
// matches!(result, Ok(_)),
// "got error: {}",
// result.unwrap_err()
// );
// let resp = result.unwrap();
//
// let oauth = resp.oauth.unwrap();
// assert_eq!(oauth.steamid, "92591609556178617");
// assert_eq!(oauth.oauth_token, "1cc83205dab2979e558534dab29f6f3aa");
// assert_eq!(oauth.wgtoken, "3EDA9DEF07D7B39361D95203525D8AFE82A");
// assert_eq!(oauth.wgtoken_secure, "F31641B9AFC2F8B0EE7B6F44D7E73EA3FA48");
// assert_eq!(oauth.webcookie, "");
// }
// }
