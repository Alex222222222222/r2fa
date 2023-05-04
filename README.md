# r2fa

Rust implementation for HTOP, TOTP and steam guard tow-factor-authentication.

Use [`ring`](https://crates.io/crates/ring) `0.16.20`,
may be incompatible with other version of `ring`.

## Features

- HOTP, TOTP
  - user configurable settings
    - digits
    - secret key
    - TOTP Key time step (period)
    - TOTP Key start time (t0)
    - HOTP Key initial counter
- steam guard (not implemented yet)
  - verification
  - code generate

## Cargo Features

### qrcode

- `qrcode`
  - `qrcodegen`
  - `qrcoderead`

The `qrcode` feature is enabled by default,
need to add `default-features = false` to disable the default feature.

Or, you can enable the `qrcodegen` feature explicitly
which used to generate the qrcode with the given opt auth data.

Or, the `qrcoderead` feature
which used to read the qrcode with the given opt auth qrcode.

Both `qrcodegen` and `qrcoderead` feature use the [`image`](https://crates.io/crates/image)
crate, which will greatly increase the package size.

### log

- `log`

This feature provided log support for the library.

## TODO

- [x] log feature
- [ ] steam guard
  - [x] steam login
  - [ ] add phone number to steam
  - [ ] add steam guard method
  - [ ] remove steam guard method
  - [ ] confirmations

## Usage

### Manually Create the Struct

```rust
use libr2fa::HOTPKey;
use libr2fa::HMACType;
use libr2fa::Key;

let mut hotp_key = HOTPKey {
    key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
    // SHA1 is the default method, however it is deprecated
    hmac_type: HMACType::SHA1,
    ..Default::default()
};

let code = hotp_key.get_code().unwrap();
```

### From URI Formate String

```rust
use libr2fa::otpauth_from_uri;
use libr2fa::TOTPKey;
use libr2fa::HMACType;
use libr2fa::Key;

let totp_key1 = otpauth_from_uri("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=7&period=60");
if let Err(err) = totp_key1 {
    panic!("{}", err);
}
let mut totp_key1 = totp_key1.unwrap();

let mut totp_key2 = TOTPKey {
    name: "ACME Co:john.doe@email.com".to_string(),
    key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
    digits: 7,
    time_step: 60,
    hmac_type: HMACType::SHA256,
    issuer: Some("ACME Co".to_string()),
    ..Default::default()
    };

assert_eq!(totp_key1.get_name(), totp_key2.get_name());
assert_eq!(totp_key1.get_type(), totp_key2.get_type());
assert_eq!(totp_key1.get_code(), totp_key2.get_code());
```

If given a opt auth struct, it can also be converted to a uri formate string.

```rust
use libr2fa::HOTPKey;
use libr2fa::HMACType;
use libr2fa::Key;

let mut hotp_key = HOTPKey {
    key: "MFSWS5LGNBUXKZLBO5TGQ33JO5SWC2DGNF2WCZLIMZUXKZLXMFUGM2LVNFQWK53IMZUXK2A=".to_string(),
    // SHA1 is the default method, however it is deprecated
    hmac_type: HMACType::SHA1,
    ..Default::default()
};

let uri = hotp_key.get_uri();
```

### From URI QRCode

See the [Cargo Features](#cargo-features) part first.

The original qrcode:
![original qrcode](public/uri_qrcode_test.png)

```rust
use libr2fa::otpauth_from_uri_qrcode;
use libr2fa::TOTPKey;
use libr2fa::HMACType;
use libr2fa::Key;

let totp_key1 = otpauth_from_uri_qrcode("public/uri_qrcode_test.png");
if let Err(err) = totp_key1 {
    panic!("{}", err);
}
let mut totp_key1 = totp_key1.unwrap();

let mut totp_key2 = TOTPKey {
    name: "ACME Co:john.doe@email.com".to_string(),
    issuer: Some("ACME Co".to_string()),
    key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
    digits: 7,
    time_step: 60,
    hmac_type: HMACType::SHA256,
    ..Default::default()
};

assert_eq!(totp_key1.get_name(), totp_key2.get_name());
assert_eq!(totp_key1.get_type(), totp_key2.get_type());
assert_eq!(totp_key1.get_code(), totp_key2.get_code());
```

Or, generate the qrcode with the given opt auth data.

Note, all encoded image will be 2048x2048.

```rust
use libr2fa::otpauth_from_uri_qrcode;
use libr2fa::TOTPKey;
use libr2fa::HMACType;
use libr2fa::Key;
use libr2fa::OptAuthKey;

let totp_key = TOTPKey {
    name: "ACME Co:john.doe@email.com".to_string(),
    issuer: Some("ACME Co".to_string()),
    key: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
    digits: 7,
    time_step: 60,
    hmac_type: HMACType::SHA256,
    ..Default::default()
};

let uri = totp_key.to_uri_struct();

// convert to image::DynamicImage data
let img: image::DynamicImage = uri.into();


// Or, save to a path
uri.to_qr_code("public/uri_qrcode_encode_test.png").unwrap();
```

The encoded qrcode:
![encoded qrcode](public/uri_qrcode_encode_test.png)

## Steam API

### Phone Validate API

Test whether a phone number is valid and is a voip.

Host: `store.steampowered.com`

Endpoint: `/phone/validate`

Method: `POST`

Content-Type: `application/x-www-form-urlencoded; charset=UTF-8`

Request Body:

- `sessionID` : session id
- `phoneNumber`: phone number

Response: `json`

Response Sample:

```json
{
    "success":true,
    "number":"your phone number",
    "is_valid":true,
    "is_voip":false,
    "is_fixed":false
}
```

### Add Phone Number

This is a multi process procedure.

1. First you send you `phone number` to steam.
2. Then it is likely that steam will ask for your `Email Verification`.
3. You click the email verification link send to your mailbox.
4. You send a request to steam says that you have clicked the link.
5. Then steam will send a `sms code` to the phone number.
6. You send a request to steam that contain the `sms code`.
7. Done.

However all this process have the same `host`, `endpoint`, `method`
and `content type`.
The only difference is the `request body`.

Host: `store.steampowered.com`

Endpoint: `/phone/add_ajaxop`

Method: `POST`

Content-Type: `application/x-www-form-urlencoded; charset=UTF-8`

#### Send the phone number

Request Body:

- `op` : `get_phone_number`
- `input` : your phone number
- `sessionID` : your session id
- `confirmed` : `1`
- `checkfortos` : `1`
- `bisediting` : `0`
- `token` : `0`

Response Sample:

```json
{
    "success":true,
    "showResend":false,
    "state":"email_verification",
    "errorText":"",
    "token":"0",
    "phoneNumber":"your phone number"
}
```

The `state` is `email_verification` means you could go for email verification.
The `state` is `get_sms_code` means you could go for check `sms code`.

#### Email Verification

Request Body:

- `op` : `email_verification`
- `input` : empty
- `sessionID` : your session id
- `confirmed` : `1`
- `checkfortos` : `1`
- `bisediting` : `0`
- `token` : `0`

Response Sample:

```json
{
    "success":true,
    "showResend":false,
    "state":"get_sms_code",
    "errorText":"",
    "token":"0",
    "inputSize":"20",
    "maxLength":"5"
}
```

The `state` is `email_verification` means you could go for email verification.
The `state` is `get_sms_code` means you could go for check `sms code`.

#### SMS Code Verification

Request Body:

- `op` : `get_sms_code`
- `input` : sms code you receive
- `sessionID` : your session id
- `confirmed` : `1`
- `checkfortos` : `1`
- `bisediting` : `0`
- `token` : `0`

Response Sample:

```json
{
    "success":true,
    "showResend":false,
    "state":"done",
    "errorText":"",
    "token":"0",
    "vac_policy":0,
    "tos_policy":2,
    "showDone":true,
    "maxLength":"5"
}
```

The `state` is `done` means the process is done.
