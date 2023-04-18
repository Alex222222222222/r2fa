use serde::{Deserialize, Deserializer};

/// Response for /phone/validate endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct PhoneValidateResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// unknown
    pub number: String,
    /// is the number valid
    pub is_valid: bool,
    /// is the number a mobile number
    #[serde(default)]
    pub is_voip: bool,
    /// unknown
    #[serde(default)]
    pub is_fixed: bool,
}

/// Response for /phone/add_ajaxop endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct PhoneAjaxResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// state
    #[serde(default, deserialize_with = "deserialize_phone_ajax_state")]
    pub state: String,
    /// error text
    ///
    /// if not empty, `success` is false
    #[serde(rename = "errorText")]
    pub error_text: String,
    /// unknown
    #[serde(default, rename = "showResend")]
    pub show_resend: bool,
    /// unknown
    ///
    /// Personal guess: what the you send in the request
    #[serde(default)]
    pub input: String,
    /// unknown
    #[serde(default)]
    pub token: String,
    /// unknown
    #[serde(default, rename = "inputSize")]
    pub input_size: String,
    /// unknown
    #[serde(default, rename = "maxLength")]
    pub max_length: String,
    /// unknown
    #[serde(default, rename = "vac_policy")]
    pub vac_policy: i64,
    /// unknown
    #[serde(default, rename = "tos_policy")]
    pub tos_policy: i64,
    /// unknown
    #[serde(default, rename = "showDown")]
    pub show_down: bool,
}

/// the state sometimes is a bool and sometimes a string
fn deserialize_phone_ajax_state<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::String(s) => Ok(s),
        _ => Err(serde::de::Error::custom("invalid type")),
    }
}
