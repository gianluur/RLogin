use anyhow::{Context, Result, bail};
use std::{
    env,
    fs::read_to_string,
    io::{Write, stdin, stdout},
    path::PathBuf,
};

use nix::unistd::{Gid, Uid, setgid, setuid};
use yescrypt::{self, PasswordHasher, PasswordVerifier, Yescrypt};

#[derive(Debug)]
struct PasswdInfo {
    user: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

impl PasswdInfo {
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

        // I will not run this on my main system because otherwise it would mess up with my actual env
        // self.set_uid_gid()?;

        Ok(())
    }

    fn set_uid_gid(&self) -> Result<()> {
        setuid(Uid::from_raw(self.uid)).context("[ERROR] Failed to set user id")?;
        setgid(Gid::from_raw(self.gid)).context("[ERROR] Failed to set groupd id")?;

        Ok(())
    }
}

struct ShadowInfo {
    username: String,
    hashed_password: String,
    // I would use this field later on currently, for this implementation i don't really need it
    // last_pass_change: u32,
    // min_password_age: u32,
    // max_password_age: u32,
    // warning_period: u32,
    // inactivity_period: u32,
    // expiration_date: u32,
}

impl ShadowInfo {
    fn new(username: &str, password: String) -> Result<Self> {
        use yescrypt::password_hash::Error::PasswordInvalid;
        let yescrypt = Yescrypt::default();

        let stored_password = Self::get_password_from_file(&username)?;
        let current_password = password.as_bytes();

        let hashed_password = yescrypt
            .hash_password(&password.as_bytes())
            .context("[ERROR] Failed to has current password")?
            .to_string();

        return match yescrypt.verify_password(current_password, stored_password.as_str()) {
            Ok(_) => Ok(Self {
                username: username.to_string(),
                hashed_password,
            }),
            Err(PasswordInvalid) => bail!("[ERROR] The inserted password is invalid"),
            Err(_) => bail!(
                "[ERROR] An error has occured during the password verification between the stored and cirrent password"
            ),
        };
    }

    fn get_password_from_file(username: &str) -> Result<String> {
        let path = PathBuf::from("/etc/shadow");
        let file = read_to_string(path).context("[ERROR] Failed to open shadow file")?;
        for lines in file.lines() {
            let fields: Vec<&str> = lines.split(':').collect();
            if fields.first() == Some(&username) {
                return Ok(fields[1].to_owned());
            }
        }

        bail!("[ERROR] Username not found in the shadow file")
    }
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

fn get_user_env(username: &str) -> Result<PasswdInfo> {
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

            return Ok(PasswdInfo::new(user, uid, gid, home, shell));
        }
    }

    bail!("[ERROR] Username isn't inside passwd");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let username = &if args.len() > 1 {
        &args[1]
    } else {
        &input("username: ", false)?
    };
    println!("{username}");

    let password = input("password: ", true)?;

    get_user_env(username)?.apply()?;

    ShadowInfo::new(username, password)?;

    print!("Password matches!");

    Ok(())
}
