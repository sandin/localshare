use std::error::Error;
use std::fs;
use dirs;

pub struct Config {
    pub authorized_keys_file: Option<std::path::PathBuf>,
    pub keyring_file: Option<std::path::PathBuf>,
}


pub fn read_user_config() -> Result<Config, Box<dyn Error>> {
    let mut config = Config { authorized_keys_file: None, keyring_file: None };

    let mut user_config_dir = dirs::config_dir().unwrap();
    user_config_dir.push(".localshare");
    if !user_config_dir.exists() {
        fs::create_dir_all(&user_config_dir)?;
    }
    println!("UserConfigDir: {:?}", user_config_dir);

    let mut authorized_keys_file = user_config_dir.clone();
    authorized_keys_file.push("authorized_keys");
    if authorized_keys_file.exists() {
        config.authorized_keys_file = Some(authorized_keys_file);
    }

    let mut keyring_file = user_config_dir.clone();
    keyring_file.push("default.keyring");
    if keyring_file.exists() {
        config.keyring_file = Some(keyring_file);
    }

    Ok(config)
}