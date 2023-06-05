use rand::Rng;

use crate::{error::Error, Key};

#[ignore = "Use confidential data"]
#[test]
fn test_steam_key() -> Result<(), Error> {
    let mafile = crate::steam::MaFile::from_file("./public/mafile_test_real.mafile")?;
    let mut steam_key = crate::SteamKey::from_mafile(mafile)?;
    let code = steam_key.get_code()?;
    println!("steam code: {}", code);
    Ok(())
}

#[test]
fn test_steam_two_factor_secret_parse() -> Result<(), Error> {
    let mut token = [0_u8; 20];
    // generate random token
    let mut rng = rand::thread_rng();
    for i in token.iter_mut() {
        *i = rng.gen();
    }

    let shared_secret = data_encoding::BASE64.encode(&token);

    println!("shared_secret: {}", shared_secret);

    super::token::TwoFactorSecret::parse_shared_secret(shared_secret)?;

    Ok(())
}
