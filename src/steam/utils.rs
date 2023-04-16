use serde::{Deserialize, Deserializer};

/// Deserialize a u64 from a string.
///
/// Steam returns some u64 as a string, so we need to deserialize them as a string
pub fn deserialize_u64_from_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    s.parse::<u64>().map_err(serde::de::Error::custom)
}
