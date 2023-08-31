use blake2::{Blake2s256, Digest};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;

pub fn cal_file_checksum(filepath: &Path) -> Result<String, Box<dyn Error>> {
    let f = File::open(filepath).unwrap();
    let mut reader = BufReader::new(f);
    let mut hasher = Blake2s256::new();

    let mut buffer = [0u8; 65535];
    loop {
        let n = reader.read(&mut buffer[..])?;
        if n == 0 {
            break; // EOF
        }
        hasher.update(&buffer[..n]);
    }
    let res = hasher.finalize();
    Ok(hex::encode(&res))
}

pub struct FileChunk {}

pub fn split_file_to_chunks(filepath: &Path) -> Result<Vec<FileChunk>, Box<dyn Error>> {
    let mut vec = Vec::new();
    vec.push(FileChunk {}); // TODO

    Ok(vec)
}

// cargo test -- --nocapture cal_file_checksum_test
#[tokio::test()]
async fn cal_file_checksum_test() -> Result<(), Box<dyn Error>> {
    let filepath = Path::new("test.keyring");
    assert_eq!(
        "d6d8ba4ca8c4a881fbb296beb93f49f21861ae9256c0b7c8a2b92797cd9a1827",
        cal_file_checksum(filepath)?
    );
    Ok(())
}
