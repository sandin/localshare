use base64ct::{Base64, Encoding};
use snow::Keypair;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

pub fn serialize_key(input: &[u8]) -> String {
    return Base64::encode_string(input);
}

pub fn write_keypair_to_file(keypair: &Keypair, output: &PathBuf) -> Result<(), Box<dyn Error>> {
    let public_key = serialize_key(&keypair.public);
    let private_key = serialize_key(&keypair.private);
    let key_config = format!(
        "PublicKey = {}\nPrivateKey = {}\n",
        public_key.as_str(),
        private_key.as_str()
    );

    let mut file = File::create(output)?;
    file.write_all(key_config.as_bytes())?;
    println!("keyring saved at {:?}", output);

    Ok(())
}

pub fn read_keypair_from_file(filename: &PathBuf) -> Result<Keypair, Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let lines = content.split('\n');
    let mut public_key = None;
    let mut private_key = None;
    for line in lines {
        if line.starts_with("PublicKey = ") {
            let key = &line["PublicKey = ".len()..];
            println!("PublicKey = {}", key);
            public_key = Some(Base64::decode_vec(key).unwrap());
        } else if line.starts_with("PrivateKey = ") {
            private_key = Some(Base64::decode_vec(&line["PrivateKey = ".len()..]).unwrap());
        }
    }
    if public_key.is_none() || private_key.is_none() {
        return Err(Box::from("bad key file"));
    }

    Ok(Keypair {
        private: private_key.unwrap().clone(),
        public: public_key.unwrap().clone(),
    })
}
