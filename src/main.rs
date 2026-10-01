use anyhow::{Context, Result, bail};
use std::{
    env,
    fs::read_to_string,
    io::{Write, stdin, stdout},
    path::PathBuf,
};

use nix::unistd::{Gid, Uid, setgid, setuid};
use yescrypt::{self, PasswordVerifier, Yescrypt};

struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    fn new() -> Result<Self> {
        return Ok(Self {
            username: Self::get_username()?,
            password: Self::get_password()?,
        });
    }

    fn input(message: &str, echo_off: bool) -> Result<String> {
        print!("{message}");
        stdout().flush()?;

        if echo_off {
            return Ok(rpassword::read_password()?);
        }

        let mut buffer = String::new();
        stdin()
            .read_line(&mut buffer)
            .context("[ERROR] Failed to read input")?;
        return Ok(buffer);
    }

    fn get_username() -> Result<String> {
        if let Some(username) = env::args().nth(1) {
            return Ok(username.trim().to_string());
        } else {
            return Self::input("username: ", false);
        }
    }

    fn get_password() -> Result<String> {
        return Self::input("password: ", true);
    }
}

struct Envirorment {
    user: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

impl Envirorment {
    fn new(user: String, uid: u32, gid: u32, home: String, shell: String) -> Self {
        Self {
            user,
            uid,
            gid,
            home,
            shell,
        }
    }

    fn apply(&self) -> Result<()> {
        // unsafe {
        //     env::set_var("USER", &self.user);
        //     env::set_var("HOME", &self.home);
        //     env::set_var("SHELL", &self.shell);
        // }

        // // I will not run this on my main system because otherwise it would mess up with my actual env
        // self.set_uid_gid()?;

        Ok(())
    }

    fn set_uid_gid(&self) -> Result<()> {
        setuid(Uid::from_raw(self.uid)).context("[ERROR] Failed to set user id")?;
        setgid(Gid::from_raw(self.gid)).context("[ERROR] Failed to set groupd id")?;

        Ok(())
    }

    pub fn get(username: &str) -> Result<Envirorment> {
        let passwd_path = "/etc/passwd";
        let passwd = read_to_string(passwd_path)?;

        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.first() == Some(&username) {
                let uid = fields[2]
                    .parse::<u32>()
                    .context("[ERROR] Failed to convert uid to integer")?;

                let gid = fields[3]
                    .parse::<u32>()
                    .context("[ERROR] Failed to convert gid to integer")?;

                let user = fields[4].to_owned();

                let home = fields[5].to_owned();
                let shell = fields[6].to_owned();
                // NOTE: The check for the bash in case is empty is useless
                // because my os will always use RShell instead

                return Ok(Envirorment::new(user, uid, gid, home, shell));
            }
        }

        bail!("[ERROR] Username isn't inside passwd");
    }
}

struct PasswordInfo {
    hashed_password: String,
    // I would use this field later on currently, for this implementation i don't really need it
    // last_pass_change: u32,
    // min_password_age: u32,
    // max_password_age: u32,
    // warning_period: u32,
    // inactivity_period: u32,
    // expiration_date: u32,
}

impl PasswordInfo {
    fn password_matches(&self, password: &[u8], stored_password: &str) -> Result<bool> {
        use yescrypt::password_hash::Error::PasswordInvalid;
        let yescrypt = Yescrypt::default();

        return match yescrypt.verify_password(password, stored_password) {
            Ok(_) => Ok(true),
            Err(PasswordInvalid) => bail!("[ERROR] The inserted password is invalid"),
            Err(_) => bail!(
                "[ERROR] An error has occured during the password verification between the stored and cirrent password"
            ),
        };
    }

    fn get(username: &str) -> Result<PasswordInfo> {
        let path = PathBuf::from("/etc/shadow");
        let file = read_to_string(path).context("[ERROR] Failed to open shadow file")?;
        for lines in file.lines() {
            let fields: Vec<&str> = lines.split(':').collect();
            if fields.first() == Some(&username) {
                let hashed_password: String = fields[1].to_owned();

                return Ok(Self { hashed_password });
            }
        }

        bail!("[ERROR] Username not found in the shadow file")
    }
}

struct User {
    credentials: Credentials,
    env: Envirorment,
    pass_info: PasswordInfo,
}

impl User {
    pub fn new() -> Result<Self> {
        let credentials = Credentials::new()?;
        let username = &credentials.username.clone();

        return Ok(Self {
            credentials,
            env: Envirorment::get(username)?,
            pass_info: PasswordInfo::get(username)?,
        });
    }

    pub fn login(&self) -> Result<()> {
        let password = self.credentials.password.as_bytes();
        let stored_password = &self.pass_info.hashed_password;

        if self.pass_info.password_matches(password, stored_password)? {
            self.env.apply()?;
            println!("Everything went smoothly");
            return Ok(());
        } else {
            bail!("[ERROR] Something went wrong: ")
        }
    }
}

fn main() -> Result<()> {
    User::new()?.login()
}
