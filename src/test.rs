use crate::hotp::HOTPKey;
use crate::Key;

#[test]
fn hotp_sha1_work() {
    let mut hotp_key1 = HOTPKey {
        key: "MZZHI6LHOVUGU===".to_string(),
        counter: 4,
        hmac_type: crate::HMACType::SHA1,
        ..Default::default()
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
        key: "MZZHI6LHOVUGU===".to_string(),
        counter: 4,
        hmac_type: crate::HMACType::SHA256,
        ..Default::default()
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
        key: "MZZHI6LHOVUGU===".to_string(),
        counter: 4,
        hmac_type: crate::HMACType::SHA512,
        ..Default::default()
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

#[test]
fn uri_decoder_totp_work() {
    let totp_key1 = crate::otpauth_from_uri("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=7&period=60");
    if let Err(err) = totp_key1 {
        panic!("{}", err);
    }
    let mut totp_key1 = totp_key1.unwrap();

    let mut totp_key2 = crate::TOTPKey {
        name: "ACME Co:john.doe@email.com".to_string(),
        issuer: Some("ACME Co".to_string()),
        key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
        digits: 7,
        time_step: 60,
        hmac_type: crate::HMACType::SHA256,
        ..Default::default()
    };

    assert_eq!(totp_key1.get_name(), totp_key2.get_name());
    assert_eq!(totp_key1.get_type(), totp_key2.get_type());
    assert_eq!(totp_key1.get_code(), totp_key2.get_code());
}

#[test]
fn uri_decoder_hotp_work() {
    let hotp_key1 = crate::otpauth_from_uri("otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=7&counter=7");
    if let Err(err) = hotp_key1 {
        panic!("{}", err);
    }
    let mut hotp_key1 = hotp_key1.unwrap();

    let mut hotp_key2 = crate::HOTPKey {
        name: "ACME Co:john.doe@email.com".to_string(),
        issuer: Some("ACME Co".to_string()),
        key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
        digits: 7,
        counter: 7,
        hmac_type: crate::HMACType::SHA256,
        ..Default::default()
    };

    assert_eq!(hotp_key1.get_name(), hotp_key2.get_name());
    assert_eq!(hotp_key1.get_type(), hotp_key2.get_type());
    assert_eq!(hotp_key1.get_code(), hotp_key2.get_code());
}

#[test]
fn uri_qrcode_decoder_totp_work() {
    let totp_key1 = crate::otpauth_from_uri_qrcode("public/uri_qrcode_test.png");
    if let Err(err) = totp_key1 {
        panic!("{}", err);
    }
    let mut totp_key1 = totp_key1.unwrap();

    let mut totp_key2 = crate::TOTPKey {
        name: "ACME Co:john.doe@email.com".to_string(),
        issuer: Some("ACME Co".to_string()),
        key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
        digits: 7,
        time_step: 60,
        hmac_type: crate::HMACType::SHA256,
        ..Default::default()
    };

    assert_eq!(totp_key1.get_name(), totp_key2.get_name());
    assert_eq!(totp_key1.get_type(), totp_key2.get_type());
    assert_eq!(totp_key1.get_code(), totp_key2.get_code());
}

#[test]
fn uri_qrcode_encoder_work() {
    let uri = crate::URI::new_from_uri("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=7&period=60".to_string());

    uri.to_qr_code("public/uri_qrcode_encode_test.png").unwrap();

    let totp_key1 = crate::otpauth_from_uri_qrcode("public/uri_qrcode_encode_test.png");
    if let Err(err) = totp_key1 {
        panic!("{}", err);
    }
    let mut totp_key1 = totp_key1.unwrap();

    let mut totp_key2 = crate::TOTPKey {
        name: "ACME Co:john.doe@email.com".to_string(),
        issuer: Some("ACME Co".to_string()),
        key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
        digits: 7,
        time_step: 60,
        hmac_type: crate::HMACType::SHA256,
        ..Default::default()
    };

    assert_eq!(totp_key1.get_name(), totp_key2.get_name());
    assert_eq!(totp_key1.get_type(), totp_key2.get_type());
    assert_eq!(totp_key1.get_code(), totp_key2.get_code());
}
