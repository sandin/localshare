mod codec;
mod file_chunk;
mod keyring;
mod message;
mod noise;

use bytes::Bytes;
use clap::{arg, Command};
use futures::SinkExt;
use std::error::Error;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::codec::NoiseMessageCodec;
use crate::file_chunk::split_file_to_chunks;
use crate::keyring::{read_keypair_from_file, write_keypair_to_file};
use crate::message::{Deserializable, FileHeader, Message, MessageType, PullRequest, Serializable};
use crate::noise::{gen_keypair, initiator_handshake, responder_handshake};

struct Context {
    keypair: snow::Keypair,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("localshare")
        .bin_name("localshare")
        .subcommand_required(true)
        .subcommand(
            Command::new("server")
                .about("start server")
                .arg(
                    arg!(<ADDR> "the server address")
                        .default_value("0.0.0.0:8080")
                        .required(false),
                )
                .arg(
                    arg!(-k --key <FILE> "the keyring file")
                        .value_parser(clap::value_parser!(std::path::PathBuf))
                        .required(true),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("pull")
                .about("pull a remote file from the peer node")
                .arg(arg!(<PATH> "remote file path"))
                .arg(arg!(-p --peer <ADDR> "the peer address"))
                .arg(
                    arg!(-k --key <FILE> "the keyring file")
                        .value_parser(clap::value_parser!(std::path::PathBuf))
                        .required(true),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("keygen")
                .about("gen keyring")
                .arg(
                    arg!(<OUTPUT> "the output file")
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
                .arg_required_else_help(true),
        );
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("server", matches)) => {
            let addr = matches.get_one::<String>("ADDR").expect("required");
            let keyfile = matches
                .get_one::<std::path::PathBuf>("key")
                .expect("required");
            start_server(addr, keyfile).await?;
        }
        Some(("pull", matches)) => {
            let filepath = matches.get_one::<String>("PATH").expect("required");
            let addr = matches.get_one::<String>("peer").expect("required");
            let keyfile = matches
                .get_one::<std::path::PathBuf>("key")
                .expect("required");
            pull_file(filepath.clone(), addr, keyfile).await?;
        }
        Some(("keygen", matches)) => {
            let output = matches
                .get_one::<std::path::PathBuf>("OUTPUT")
                .expect("required");
            gen_keyring_file(output).await?;
        }
        _ => unreachable!("clap should ensure we don't get here"),
    };

    Ok(())
}

async fn gen_keyring_file(output: &std::path::PathBuf) -> Result<(), Box<dyn Error>> {
    let keypair = gen_keypair()?;

    write_keypair_to_file(&keypair, output)?;
    println!("keyring saved at {:?}", output);

    Ok(())
}

async fn start_server(addr: &String, keyfile: &std::path::PathBuf) -> Result<(), Box<dyn Error>> {
    let keypair = read_keypair_from_file(keyfile)?;
    let context = Arc::new(Mutex::new(Context { keypair }));

    let server = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    loop {
        let (stream, _) = server.accept().await?;
        let context = Arc::clone(&context);

        tokio::spawn(async move {
            if let Err(e) = handle_client(context, stream).await {
                println!("failed to process connection; error = {}", e);
            }
        });
    }
}

async fn handle_client(
    context: Arc<Mutex<Context>>,
    stream: TcpStream,
) -> Result<(), Box<dyn Error>> {
    let context = context.lock().await;
    let static_key = &context.keypair.private;

    let mut transport = Framed::new(stream, NoiseMessageCodec::new());
    let noise = responder_handshake(&mut transport, static_key).await?;
    transport.codec_mut().set_noise(noise);

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let mut data = request.freeze();
                //let response = handle_request(&mut data).await?;
                //transport.send(response).await?;

                let mut msg = Message::deserialize(&mut data);
                println!("Got cmd: {:?}", msg);

                match MessageType::try_from(msg.cmd) {
                    Ok(MessageType::Ping) => {
                        let msg = Message {
                            cmd: MessageType::Pong as u32,
                            payload: Bytes::copy_from_slice(b"Secret Pong"),
                        };
                        println!("Send msg: {:?}", msg);
                        transport.send(msg.serialize()).await?;
                    }
                    Ok(MessageType::Pull) => {
                        let pull_request = PullRequest::deserialize(&mut msg.payload);
                        let filepath = Path::new(&pull_request.filepath);
                        if !filepath.exists() {
                            let msg = Message {
                                cmd: MessageType::Text as u32,
                                payload: Bytes::from(format!(
                                    "Error: {} file is not exists!",
                                    filepath.to_str().unwrap()
                                )),
                            };
                            println!("Send msg: {:?}", msg);
                            transport.send(msg.serialize()).await?;
                        }

                        let msg = Message {
                            cmd: MessageType::FileHeader as u32,
                            payload: FileHeader::new(&filepath).serialize(),
                        };
                        println!("Send msg: {:?}", msg);
                        transport.send(msg.serialize()).await?;

                        let chunks = split_file_to_chunks(&filepath).unwrap();
                        for chunk in chunks {
                            let msg = Message {
                                cmd: MessageType::FileChunk as u32,
                                payload: Bytes::from("chunk"), // TODO: chunk.serialize(),
                            };
                            println!("Send msg: {:?}", msg);
                            transport.send(msg.serialize()).await?;
                        }
                    }
                    Ok(MessageType::Push) => {
                        // TODO
                    }
                    _ => {
                        println!("unknown cmd: {}", msg.cmd);
                        break; // close this connection
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

async fn handle_request(data: &mut Bytes) -> Result<Bytes, Box<dyn Error>> {
    let mut msg = Message::deserialize(data);
    println!("Got cmd: {:?}", msg);

    match MessageType::try_from(msg.cmd) {
        Ok(MessageType::Ping) => {
            let resp = Message {
                cmd: MessageType::Pong as u32,
                payload: Bytes::copy_from_slice(b"Secret Pong"),
            };
            println!("Send msg: {:?}", resp);
            return Ok(resp.serialize());
        }
        Ok(MessageType::Pull) => {
            let pull_request = PullRequest::deserialize(&mut msg.payload);
            let filepath = Path::new(&pull_request.filepath);
            if !filepath.exists() {
                return Ok(Message {
                    cmd: MessageType::Text as u32,
                    payload: Bytes::from(format!(
                        "Error: {} file is not exists!",
                        filepath.to_str().unwrap()
                    )),
                }
                .serialize());
            }

            return Ok(Message {
                cmd: MessageType::FileHeader as u32,
                payload: FileHeader::new(filepath).serialize(),
            }
            .serialize());
        }
        Ok(MessageType::Push) => {
            // TODO
        }
        _ => {
            println!("unknown cmd: {}", msg.cmd);
        }
    }
    Ok(Bytes::new())
}

async fn pull_file(
    filepath: String,
    addr: &String,
    keyfile: &std::path::PathBuf,
) -> Result<(), Box<dyn Error>> {
    let keypair = read_keypair_from_file(keyfile)?;
    let static_key = &keypair.private;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut transport = Framed::new(stream, NoiseMessageCodec::new());

    let noise = initiator_handshake(&mut transport, static_key).await?;
    transport.codec_mut().set_noise(noise);

    let cmd = Message {
        cmd: MessageType::Pull as u32,
        payload: PullRequest::new(filepath).serialize(),
    };
    println!("Send msg: {:?}", cmd);
    transport.send(cmd.serialize()).await?;

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let mut data = request.freeze();
                let mut msg = Message::deserialize(&mut data);
                println!("Got msg: {:?}", msg);
                if msg.cmd == MessageType::FileHeader as u32 {
                    let file_header = FileHeader::deserialize(&mut msg.payload);
                    println!("file_header: {:?}", file_header);
                    // TODO
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

// cargo test -- --nocapture client_test
#[tokio::test()]
async fn client_test() -> Result<(), Box<dyn Error>> {
    Ok(())
}
