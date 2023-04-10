use crate::hotp::HOTPKey;
use crate::Key;

#[test]
fn hotp_sha1_work() {
    let mut hotp_key1 = HOTPKey {
        name: "".to_string(),
        key: "MZZHI6LHOVUGU===".to_string(),
        digits: 6,
        counter: 0,
        recovery_codes: Vec::default(),
        hmac_type: crate::HMACType::SHA1,
    };

    let hotp_key2 =
        libauthenticator::hotp("MZZHI6LHOVUGU===", 5, libauthenticator::Algorithm::SHA1, 6)
            .unwrap()
            .to_string();

    assert_eq!(hotp_key1.get_code().unwrap(), hotp_key2);
}

#[test]
fn hotp_sha256_work() {
    let mut hotp_key1 = HOTPKey {
        name: "".to_string(),
        key: "MZZHI6LHOVUGU===".to_string(),
        digits: 6,
        counter: 0,
        recovery_codes: Vec::default(),
        hmac_type: crate::HMACType::SHA256,
    };

    let hotp_key2 = libauthenticator::hotp(
        "MZZHI6LHOVUGU===",
        5,
        libauthenticator::Algorithm::SHA256,
        6,
    )
    .unwrap()
    .to_string();

    assert_eq!(hotp_key1.get_code().unwrap(), hotp_key2);
}

#[test]
fn hotp_sha512_work() {
    let mut hotp_key1 = HOTPKey {
        name: "".to_string(),
        key: "MZZHI6LHOVUGU===".to_string(),
        digits: 6,
        counter: 0,
        recovery_codes: Vec::default(),
        hmac_type: crate::HMACType::SHA512,
    };

    let hotp_key2 = libauthenticator::hotp(
        "MZZHI6LHOVUGU===",
        5,
        libauthenticator::Algorithm::SHA512,
        6,
    )
    .unwrap()
    .to_string();

    assert_eq!(hotp_key1.get_code().unwrap(), hotp_key2);
}

#[test]
fn totp_sha1_work() {
    let mut totp_key1 = crate::TOTPKey {
        key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
        hmac_type: crate::HMACType::SHA1,
        ..Default::default()
    };

    let totp_key2 = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(
            "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
        )
        .to_bytes()
        .unwrap(),
    );
    if let Err(err) = totp_key2 {
        panic!("{}", err);
    }
    let totp_key2 = totp_key2.unwrap();

    assert_eq!(
        totp_key1.get_code().unwrap(),
        totp_key2.generate_current().unwrap()
    )
}

#[test]
fn totp_sha256_work() {
    let mut totp_key1 = crate::TOTPKey {
        key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
        hmac_type: crate::HMACType::SHA256,
        ..Default::default()
    };

    let totp_key2 = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA256,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(
            "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
        )
        .to_bytes()
        .unwrap(),
    );
    if let Err(err) = totp_key2 {
        panic!("{}", err);
    }
    let totp_key2 = totp_key2.unwrap();

    assert_eq!(
        totp_key1.get_code().unwrap(),
        totp_key2.generate_current().unwrap()
    )
}

#[test]
fn totp_sha512_work() {
    let mut totp_key1 = crate::TOTPKey {
        key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
        hmac_type: crate::HMACType::SHA512,
        ..Default::default()
    };

    let totp_key2 = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA512,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(
            "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
        )
        .to_bytes()
        .unwrap(),
    );
    if let Err(err) = totp_key2 {
        panic!("{}", err);
    }
    let totp_key2 = totp_key2.unwrap();

    assert_eq!(
        totp_key1.get_code().unwrap(),
        totp_key2.generate_current().unwrap()
    )
}
