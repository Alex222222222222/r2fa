mod i_two_factor_service;
mod login;

pub use i_two_factor_service::*;
pub use login::*;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SteamApiResponse<T> {
    pub response: T,
}
