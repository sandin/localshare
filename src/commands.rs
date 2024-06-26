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
use std::time::SystemTime;

use crate::codec::NoiseMessageCodec;
use crate::message::PushRequest;
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
    root_dir: &String,
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
    pull_request: PullRequest,
) -> Result<(), Box<dyn Error>> {
    let filepath = Path::new(&pull_request.filepath);
    println!("filepath: {:?}, root_dir: {:?}", &filepath, &root_dir);
    if !filepath.exists() || (root_dir != "/" && !filepath.starts_with(root_dir)) {
        let msg = Message {
            cmd: MessageType::PlainText as u32,
            payload: Bytes::from(format!(
                "Error: {} file is not exists!",
                filepath.to_str().unwrap()
            )),
        };
        transport.send(msg.serialize()).await?;
        println!("<- : {}", msg);

        return Ok(()); // TODO: return Err(&"Error".to_owned());
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
    println!("-> : {}", msg);

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
        transport.send(msg.serialize()).await?;
        //println!("-> : {}", msg);
    }
    println!("Send file {:?}, size: {:?}, checksum: {:?}", &file_header.filename, &file_header.filesize, &file_header.checksum);

    Ok(())
}

// [client]
pub async fn handle_pull_response(
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
    file_header: Option<FileHeader>
) -> Result<(), Box<dyn Error>> {
    let mut file_header: Option<FileHeader> = file_header;
    let mut f: Option<File> = None;
    let mut local_file_path: Option<PathBuf> = None;
    let mut recv_count = 0;
    let mut error_msg: Option<String> = None;
    let start_time = SystemTime::now();

    if let Some(header) = &file_header {
        let mut file_path = PathBuf::new();
        file_path.push(&header.filename);
        f = Some(File::create(&file_path)?);
        local_file_path = Some(file_path);
    } 

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let mut data = request.freeze();
                let mut msg = Message::deserialize(&mut data);
                if msg.cmd == MessageType::FileHeader as u32 {
                    println!("<- : {}", msg);
                    let header = FileHeader::deserialize(&mut msg.payload);
                    let mut file_path = PathBuf::new();
                    file_path.push(&header.filename); // TODO: dir
                    f = Some(File::create(&file_path)?);
                    local_file_path = Some(file_path);
                    file_header = Some(header);
                } else if msg.cmd == MessageType::FileChunk as u32 {
                    //println!("<- : {}", msg);
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
                } else if msg.cmd == MessageType::PlainText as u32 {
                    println!("<- : {}", msg);
                    error_msg = Some(String::from_utf8_lossy(&msg.payload).to_string());
                    break;
                } else {
                    break;
                }
            }
            Err(e) => {
                return Err(e.into());
            },
        }
    }
    let cost_sec = start_time.elapsed().unwrap().as_secs_f64();
    let speed_kb_pre_sec = if recv_count != 0 && cost_sec != 0.0 { recv_count as f64 / 1024.0 / cost_sec } else { 0.0 };

    match error_msg {
        Some(error_msg) => {
            println!("Error message: {:?}", error_msg);
        },
        None => {
            if let Some(file_header) = &file_header {
                if recv_count == file_header.filesize as usize {
                    println!("Got file {:?}, size: {:?}, checksum: {:?}, speed: {:.2} kb/s", &local_file_path, &file_header.filesize, &file_header.checksum, speed_kb_pre_sec);
                } else {
                    println!("Can not get the file {}, expect file size {}, actual revc size {}", file_header.filename, file_header.filesize, recv_count);
                    if let Some(local_file_path) = &local_file_path {
                        remove_file(local_file_path)?;
                    }
                }
            }
        }
    }
  
    Ok(())
}

// [server]
pub async fn handle_push_request(
    root_dir: &String,
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
    push_request: PushRequest,
) -> Result<(), Box<dyn Error>> {
    let filepath = Path::new(&push_request.remote_filepath);
    println!("filepath: {:?}, root_dir: {:?}", &filepath, &root_dir);
    if /* filepath.exists() || */ (root_dir != "/" && !filepath.starts_with(root_dir)) {
        let msg = Message {
            cmd: MessageType::PlainText as u32,
            payload: Bytes::from(format!(
                "Error: {} file is not exists!",
                filepath.to_str().unwrap()
            )),
        };
        transport.send(msg.serialize()).await?;
        println!("-> : {}", msg);

        return Ok(()); // TODO: return Err(&"Error".to_owned());
    }

    let msg = Message {
        cmd: MessageType::PushAck as u32,
        payload: Bytes::new()
    };
    transport.send(msg.serialize()).await?;
    println!("-> : {}", msg);

    let mut file_header = push_request.file_header;
    file_header.filename = filepath.to_string_lossy().to_string();
    handle_pull_response(transport, Some(file_header)).await
}

// [client]
pub async fn handle_push_response(
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
    local_file: PathBuf,
    file_size: u64,
    remote_file_path: PathBuf
) -> Result<(), Box<dyn Error>> {
    let mut error_msg: Option<String> = None;
    let start_time = SystemTime::now();
    let mut send_count = 0;

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let mut data = request.freeze();
                let msg = Message::deserialize(&mut data);
                if msg.cmd == MessageType::PushAck as u32 {
                    println!("<- : {}", msg);

                    // send file chunks
                    let f = File::open(&local_file).unwrap();
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
                        transport.send(msg.serialize()).await?;
                        println!("-> : {}", msg);
                        send_count += n;
                    }
                    break;
                } else if msg.cmd == MessageType::PlainText as u32 {
                    println!("<- : {}", msg);
                    error_msg = Some(String::from_utf8_lossy(&msg.payload).to_string());
                    break;
                } else {
                    break;
                }
            }
            Err(e) => {
                return Err(e.into());
            },
        }
    }
    let cost_sec = start_time.elapsed().unwrap().as_secs_f64();
    let speed_kb_pre_sec = if send_count != 0 && cost_sec != 0.0 { send_count as f64 / 1024.0 / cost_sec } else { 0.0 };

    match error_msg {
        Some(error_msg) => {
            println!("Error message: {:?}", error_msg);
        },
        None => {
            if send_count == file_size as usize {
                println!("Send file {:?} -> {:?}, size: {:?}, speed: {:.2} kb/s", &local_file, remote_file_path, file_size, speed_kb_pre_sec);
            } else {
                println!("Can not send the file {:?}, expect file size {}, actual send size {}", &local_file, send_count, file_size);
            }
        }
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
