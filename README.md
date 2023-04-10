# r2fa

Rust implementation for HTOP, TOTP and steam guard tow-factor-authentication.

Use [`ring`](https://crates.io/crates/ring) `0.16.20`,
may be incompatible with other version of `ring`.

## Usage

```rust
use libr2fa::HOTPKey;
use libr2fa::HMACType;
use libr2fa::Key;

let mut hotp_key = HOTPKey {
    name: "".to_string(),
    key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
    digits: 6,
    counter: 0,
    recovery_codes: Vec::default(),
    hmac_type: HMACType::SHA1,
};

let code = hotp_key.get_code().unwrap();
```
