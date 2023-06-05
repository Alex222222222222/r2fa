use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaFile {
    pub account_name: String,
    pub device_id: String,
    pub identity_secret: String,
    pub revocation_code: String,
    pub secret_1: String,
    pub serial_number: u64,
    pub server_time: u64,
    pub shared_secret: String,
    pub status: u64,
    pub token_gid: String,
    pub uri: String,
}

impl MaFile {
    /// load a mafile from a string
    ///
    /// ```rust
    /// use libr2fa::steam::MaFile;
    ///
    /// let mafile = MaFile::from_string(r#"{
    ///    "account_name": "test",
    ///    "device_id": "test",
    ///    "identity_secret": "test",
    ///    "revocation_code": "test",
    ///    "secret_1": "test",
    ///    "serial_number": 0,
    ///    "server_time": 0,
    ///    "shared_secret": "1Yl+tt/6w2dZEG51M8P6oc2x/cY=",
    ///    "status": 0,
    ///    "token_gid": "test",
    ///    "uri": "test"
    /// }"#);
    ///
    /// assert!(mafile.is_ok());
    ///
    /// let mafile = mafile.unwrap();
    ///
    /// assert_eq!(mafile.account_name, "test");
    /// assert_eq!(mafile.device_id, "test");
    /// assert_eq!(mafile.identity_secret, "test");
    /// assert_eq!(mafile.revocation_code, "test");
    /// assert_eq!(mafile.secret_1, "test");
    /// assert_eq!(mafile.serial_number, 0);
    /// assert_eq!(mafile.server_time, 0);
    /// assert_eq!(mafile.shared_secret, "1Yl+tt/6w2dZEG51M8P6oc2x/cY=");
    /// assert_eq!(mafile.status, 0);
    /// assert_eq!(mafile.token_gid, "test");
    /// assert_eq!(mafile.uri, "test");
    /// ```
    pub fn from_string(s: &str) -> Result<Self, crate::Error> {
        let mafile = serde_json::from_str(s);
        if let Err(e) = mafile {
            return Err(crate::Error::SteamSerdeError(
                "Error in convert json to mafile".to_string(),
                s.to_string(),
                e.to_string(),
            ));
        }

        Ok(mafile.unwrap())
    }

    /// load a mafile from a file
    ///
    /// ```rust
    /// use libr2fa::steam::MaFile;
    ///
    /// let mafile = MaFile::from_file("./public/mafile_test.mafile");
    ///
    /// assert!(mafile.is_ok());
    ///
    /// let mafile = mafile.unwrap();
    ///
    /// assert_eq!(mafile.account_name, "test");
    /// assert_eq!(mafile.device_id, "test");
    /// assert_eq!(mafile.identity_secret, "test");
    /// assert_eq!(mafile.revocation_code, "test");
    /// assert_eq!(mafile.secret_1, "test");
    /// assert_eq!(mafile.serial_number, 0);
    /// assert_eq!(mafile.server_time, 0);
    /// assert_eq!(mafile.shared_secret, "1Yl+tt/6w2dZEG51M8P6oc2x/cY=");
    /// assert_eq!(mafile.status, 0);
    /// assert_eq!(mafile.token_gid, "test");
    /// assert_eq!(mafile.uri, "test");
    /// ```
    ///
    /// // ./public/mafile_test.mafile
    /// ```json
    /// {
    ///   "account_name": "test",
    ///   "device_id": "test",
    ///   "identity_secret": "test",
    ///   "revocation_code": "test",
    ///   "secret_1": "test",
    ///   "serial_number": 0,
    ///   "server_time": 0,
    ///   "shared_secret": "1Yl+tt/6w2dZEG51M8P6oc2x/cY=",
    ///   "status": 0,
    ///   "token_gid": "test",
    ///   "uri": "test"
    /// }
    /// ```
    pub fn from_file(path: &str) -> Result<Self, crate::Error> {
        let s = std::fs::read_to_string(path);
        if let Err(e) = s {
            return Err(crate::Error::IOError(
                "Error in read mafile".to_string(),
                path.to_string(),
                e.to_string(),
            ));
        }

        Self::from_string(&s.unwrap())
    }

    /// save a mafile to a string
    ///
    /// ```rust
    /// use libr2fa::steam::MaFile;
    ///
    /// let mafile = MaFile::from_string(r#"{
    ///    "account_name": "test",
    ///    "device_id": "test",
    ///    "identity_secret": "test",
    ///    "revocation_code": "test",
    ///    "secret_1": "test",
    ///    "serial_number": 0,
    ///    "server_time": 0,
    ///    "shared_secret": "1Yl+tt/6w2dZEG51M8P6oc2x/cY=",
    ///    "status": 0,
    ///    "token_gid": "test",
    ///    "uri": "test"
    /// }"#);
    ///
    /// assert!(mafile.is_ok());
    ///
    /// let mafile = mafile.unwrap();
    ///
    /// let s = mafile.to_string();
    ///
    /// assert!(s.is_ok());
    ///
    /// let s = s.unwrap();
    ///
    /// println!("{}", s);
    /// ```
    pub fn to_string(&self) -> Result<String, crate::Error> {
        let s = serde_json::to_string(self);
        if let Err(e) = s {
            return Err(crate::Error::SteamSerdeError(
                "Error in convert mafile to json".to_string(),
                "".to_string(),
                e.to_string(),
            ));
        }

        Ok(s.unwrap())
    }

    /// save a mafile to a file
    ///
    /// ```rust
    /// use libr2fa::steam::MaFile;
    ///
    /// let mafile = MaFile::from_string(r#"{
    ///    "account_name": "test",
    ///    "device_id": "test",
    ///    "identity_secret": "test",
    ///    "revocation_code": "test",
    ///    "secret_1": "test",
    ///    "serial_number": 0,
    ///    "server_time": 0,
    ///    "shared_secret": "1Yl+tt/6w2dZEG51M8P6oc2x/cY=",
    ///    "status": 0,
    ///    "token_gid": "test",
    ///    "uri": "test"
    /// }"#);
    ///
    /// assert!(mafile.is_ok());
    ///
    /// let mafile = mafile.unwrap();
    ///
    /// let res = mafile.to_file("./public/mafile_save_test.mafile");
    ///
    /// assert!(res.is_ok());
    /// ```
    pub fn to_file(&self, path: &str) -> Result<(), crate::Error> {
        let s = self.to_string()?;

        let res = std::fs::write(path, s);
        if let Err(e) = res {
            return Err(crate::Error::IOError(
                "Error in write mafile".to_string(),
                path.to_string(),
                e.to_string(),
            ));
        }

        Ok(())
    }
}
