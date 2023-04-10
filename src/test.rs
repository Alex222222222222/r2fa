use crate::hotp::HOTPKey;
use crate::Key;

#[test]
fn htop_sha1_work() {
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
fn htop_sha256_work() {
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
fn htop_sha512_work() {
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
