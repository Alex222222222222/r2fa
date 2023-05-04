use crate::error;

#[ignore = "requires user input"]
#[test]
fn steam_login_new() {
    // ask for username
    let mut username = String::new();
    println!("Please enter your username: ");
    std::io::stdin().read_line(&mut username).unwrap();
    let username = username.trim().to_string();

    // ask for password
    let mut password = String::new();
    println!("Please enter your password: ");
    std::io::stdin().read_line(&mut password).unwrap();
    let password = password.trim().to_string();

    let mut login = super::UserLogin::new(username.to_string(), password);
    let mut loops = 0;

    println!("Logging in as {}...", username);

    loop {
        match login.login() {
            Ok(session) => {
                println!("Logged in successfully!");
                println!("Session: {:?}", session);

                // save the session info to "public/steam_session.json"
                let session_file = std::fs::File::create("public/steam_session.json").unwrap();
                serde_json::to_writer(session_file, &session).unwrap();

                break;
            }
            Err(error) => {
                println!("Error: {:?}", error);
                match error {
                    error::Error::SteamLoginError(error::SteamLoginError::NeedCaptcha {
                        captcha_gid,
                    }) => {
                        println!("Please enter the captcha code for gid {}: ", captcha_gid);
                        let mut captcha_text = String::new();
                        std::io::stdin().read_line(&mut captcha_text).unwrap();
                        login.captcha_text = captcha_text.trim().to_string();
                        login.captcha_gid = captcha_gid;
                    }
                    error::Error::SteamLoginError(error::SteamLoginError::NeedEmail) => {
                        println!("Please enter the email code: ");
                        let mut email_code = String::new();
                        std::io::stdin().read_line(&mut email_code).unwrap();
                        login.email_code = email_code.trim().to_string();
                    }
                    error::Error::SteamLoginError(error::SteamLoginError::Need2FA) => {
                        println!("Please enter the two factor code: ");
                        let mut two_factor_code = String::new();
                        std::io::stdin().read_line(&mut two_factor_code).unwrap();
                        login.two_factor_code = two_factor_code.trim().to_string();
                    }
                    _ => {
                        println!("Unknown error, exiting...");
                        break;
                    }
                }
            }
        }
        loops += 1;
        if loops > 2 {
            println!("Too many loops, exiting...");
            break;
        }
    }
}

#[ignore = "requires confidential data"]
#[test]
fn steam_login_with_session() {
    // load the session info from "public/steam_session.json"
    let session_file = std::fs::File::open("public/steam_session.json").unwrap();
    let session: super::steam_api::Session = serde_json::from_reader(session_file).unwrap();

    let mut api_client = super::steam_api::SteamApiClient::new(Some(session));

    // verify login
    let res = api_client.verify_login();

    println!("Result: {:?}", res);

    assert!(res.is_ok());
}

#[ignore = "requires confidential data"]
#[test]
fn steam_remove_authenticator() {
    // load the session info from "public/steam_session.json"
    let session_file = std::fs::File::open("public/steam_session.json").unwrap();
    let session: super::steam_api::Session = serde_json::from_reader(session_file).unwrap();

    let mut api_client = super::steam_api::SteamApiClient::new(Some(session));

    let res = api_client.verify_login();

    println!("Result: {:?}", res);
    assert!(res.is_ok());
    assert!(res.unwrap());

    // ask for revocation code
    let mut revocation_code = String::new();
    println!("Please enter your revocation code: ");
    std::io::stdin().read_line(&mut revocation_code).unwrap();
    let revocation_code = revocation_code.trim().to_string();

    let res = api_client.remove_authenticator(revocation_code);

    println!("Result: {:?}", res);
    assert!(res.is_ok());
}
