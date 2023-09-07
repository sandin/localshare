use blake2::{Blake2s256, Digest};
use bytes::{Bytes, BytesMut};
use futures::SinkExt;
use std::error::Error;
use std::fs::File;
use std::fs::remove_file;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::codec::NoiseMessageCodec;
use crate::message::{Deserializable, FileHeader, Message, MessageType, PullRequest, Serializable};

pub fn cal_file_checksum(filepath: &Path) -> Result<String, Box<dyn Error>> {
    let f = File::open(filepath).unwrap();
    let mut reader = BufReader::new(f);
    let mut hasher = Blake2s256::new();

    let mut buf = [0u8; 65535];
    loop {
        let n = reader.read(&mut buf[..])?;
        if n == 0 {
            break; // EOF
        }
        hasher.update(&buf[..n]);
    }
    let res = hasher.finalize();
    Ok(hex::encode(&res))
}


// [server]
pub async fn handle_pull_request(
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
    pull_request: PullRequest,
) -> Result<(), Box<dyn Error>> {
    let filepath = Path::new(&pull_request.filepath);
    if !filepath.exists() {
        let msg = Message {
            cmd: MessageType::PlainText as u32,
            payload: Bytes::from(format!(
                "Error: {} file is not exists!",
                filepath.to_str().unwrap()
            )),
        };
        transport.send(msg.serialize()).await?;
        println!("-> : {}", msg);
    }

    // send the file header
    let file_header = FileHeader {
        filename: filepath
            .file_name()
            .unwrap()
            .to_os_string()
            .into_string()
            .unwrap(),
        checksum: cal_file_checksum(filepath).unwrap(),
        filesize: filepath.metadata().unwrap().len(),
    };
    let msg = Message {
        cmd: MessageType::FileHeader as u32,
        payload: file_header.serialize(),
    };
    transport.send(msg.serialize()).await?;

    // send file chunks
    let f = File::open(filepath).unwrap();
    let mut reader = BufReader::new(f);
    let mut buf = [0u8; 65535];
    loop {
        let n = reader.read(&mut buf[..])?;
        if n == 0 {
            break; // EOF
        }
        let msg = Message {
            cmd: MessageType::FileChunk as u32,
            payload: Bytes::copy_from_slice(&buf[..n]),
        };
        println!("Send msg: {:?}", msg);
        transport.send(msg.serialize()).await?;
        println!("-> : {}", msg);
    }

    Ok(())
}

// [client]
pub async fn handle_pull_response(
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
) -> Result<(), Box<dyn Error>> {
    let mut file_header: Option<FileHeader> = None;
    let mut f: Option<File> = None;
    let mut local_file_path: Option<PathBuf> = None;
    let mut recv_count = 0;

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let mut data = request.freeze();
                let mut msg = Message::deserialize(&mut data);
                println!("<- : {}", msg);
                if msg.cmd == MessageType::FileHeader as u32 {
                    let header = FileHeader::deserialize(&mut msg.payload);
                    let mut file_path = PathBuf::new();
                    file_path.push(&header.filename); // TODO: dir
                    f = Some(File::create(&file_path)?);
                    local_file_path = Some(file_path);
                    file_header = Some(header);
                } else if msg.cmd == MessageType::FileChunk as u32 {
                    if let Some(file_header) = &file_header {
                        if let Some(f) = &mut f {
                            f.write_all(&msg.payload)?;
                            recv_count += msg.payload.len();

                            if recv_count >= file_header.filesize as usize {
                                if let Some(local_file_path) = &local_file_path {
                                    let checksum = cal_file_checksum(local_file_path)?;
                                    if checksum != file_header.checksum {
                                        println!("mismatch checksum");
                                        remove_file(local_file_path)?;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    if let Some(file_header) = &file_header {
        println!("Got file {}, size {}", file_header.filename, file_header.filesize)
    }
    Ok(())
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
