use crate::error;

#[test]
fn steam_login() {
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

    let mut login = super::user::UserLogin::new(username.to_string(), password.to_string());
    let mut loops = 0;

    println!("Logging in as {}...", username);

    loop {
        match login.login() {
            Ok(session) => {
                println!("Logged in successfully!");
                println!("Session: {:?}", session);
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
