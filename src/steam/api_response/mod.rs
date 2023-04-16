mod i_two_factor_service;
mod login;
mod phone_ajax;

pub use i_two_factor_service::*;
pub use login::*;
pub use phone_ajax::*;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SteamApiResponse<T> {
    pub response: T,
}
