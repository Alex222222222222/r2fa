// #[bench]
// fn hotp_sha512_1000_times(b : &mut ) {
// let mut hotp_key = HOTPKey {
// key: "MZZHI6LHOVUGU===".to_string(),
// counter: 4,
// hmac_type: crate::HMACType::SHA512,
// ..Default::default()
// };
//
// for i in 0..1000 {
// hotp_key.get_code().unwrap();
// }
// }
//
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libr2fa::Key;

pub fn otp_get_code_bench(c: &mut Criterion) {
    let mut hotp_key = libr2fa::HOTPKey {
        key: "MZZHI6LHOVUGU===".to_string(),
        counter: black_box(0),
        hmac_type: libr2fa::HMACType::SHA512,
        ..Default::default()
    };
    c.bench_function("hotp sha512 get code", |b| {
        b.iter(|| hotp_key.get_code().unwrap())
    });
    drop(hotp_key);

    let mut totp_key = libr2fa::TOTPKey {
        key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
        hmac_type: libr2fa::HMACType::SHA512,
        ..Default::default()
    };
    c.bench_function("totp sha512 get code", |b| {
        b.iter(|| totp_key.get_code().unwrap())
    });
    drop(totp_key);
}

criterion_group!(benches, otp_get_code_bench);
criterion_main!(benches);
