mod codec;
mod commands;
mod keyring;
mod message;
mod noise;
mod error;
mod config;

use bytes::{Bytes, BytesMut};
use clap::{arg, Command};
use config::read_user_config;
use futures::SinkExt;
use keyring::read_authorized_keys_from_file;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::codec::NoiseMessageCodec;
use crate::commands::{cal_file_checksum, handle_pull_request, handle_pull_response, handle_push_request, handle_push_response};
use crate::keyring::{read_keypair_from_file, write_keypair_to_file};
use crate::message::{Deserializable, FileHeader, Message, MessageType, PullRequest, PushRequest, Serializable};
use crate::noise::{gen_keypair, initiator_handshake, responder_handshake};

struct Context {
    keypair: snow::Keypair,
    authorized_keys_file: Option<std::path::PathBuf>,
    root_dir: String,
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
                        .required(false),
                )
                .arg(
                    arg!(-a --authorized_keys <FILE> "the authorized keys file")
                        .value_parser(clap::value_parser!(std::path::PathBuf))
                        .required(false),
                )
                .arg(
                    arg!(-d --dir <DIR> "the root dir")
                        .required(false),
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
                        .required(false),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("push")
                .about("push a local file to the peer node")
                .arg(arg!(<LPATH> "local file path"))
                .arg(arg!(<RPATH> "remote file path"))
                .arg(arg!(-p --peer <ADDR> "the peer address"))
                .arg(
                    arg!(-k --key <FILE> "the keyring file")
                        .value_parser(clap::value_parser!(std::path::PathBuf))
                        .required(false),
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
    let config = read_user_config().unwrap();
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("server", matches)) => {
            let addr = matches.get_one::<String>("ADDR").expect("required");
            let keyfile = matches.get_one::<std::path::PathBuf>("key").or(match &config.keyring_file {
                Some(keyring_file) => Some(&keyring_file),
                None => None,
            });
            let authorized_keys_file = matches.get_one::<std::path::PathBuf>("authorized_keys").or(match &config.authorized_keys_file {
                Some(authorized_keys_file) => Some(&authorized_keys_file),
                None => None,
            });
            let default_root_dir = "/".to_owned();
            let root_dir = matches.get_one::<String>("dir").unwrap_or(&default_root_dir);
            start_server(addr, keyfile, authorized_keys_file, root_dir.to_string()).await?;
        }
        Some(("pull", matches)) => {
            let filepath = matches.get_one::<String>("PATH").expect("required");
            let addr = matches.get_one::<String>("peer").expect("required");
            let keyfile = matches.get_one::<std::path::PathBuf>("key").or(match &config.keyring_file {
                Some(keyring_file) => Some(&keyring_file),
                None => None,
            });
            pull_file(filepath.clone(), addr, keyfile).await?;
        }
        Some(("push", matches)) => {
            let local_filepath = matches.get_one::<String>("LPATH").expect("required");
            let remote_filepath = matches.get_one::<String>("RPATH").expect("required");
            let addr = matches.get_one::<String>("peer").expect("required");
            let keyfile = matches.get_one::<std::path::PathBuf>("key").or(match &config.keyring_file {
                Some(keyring_file) => Some(&keyring_file),
                None => None,
            });
            push_file(local_filepath.clone(), remote_filepath.clone(), addr, keyfile).await?;
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

async fn start_server(addr: &String, keyfile: Option<&std::path::PathBuf>, authorized_keys_file: Option<&std::path::PathBuf>, root_dir: String) -> Result<(), Box<dyn Error>> {
    let keypair = match keyfile {
        Some(keyfile) => read_keypair_from_file(keyfile)?,
        None => gen_keypair()?
    }; 
    let authorized_keys_file: Option<std::path::PathBuf> = match authorized_keys_file {
        Some(authorized_keys_file) => Some(authorized_keys_file.clone()),
        None => None,
    };
    println!("keyfile: {:?}", keyfile);
    println!("authorized_keys_file: {:?}", authorized_keys_file);
    let context = Arc::new(Mutex::new(Context { keypair, authorized_keys_file, root_dir }));

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
    let authorized_keys = match &context.authorized_keys_file {
        Some(authorized_keys_file) => read_authorized_keys_from_file(&authorized_keys_file).unwrap(),
        None => Vec::new()
    };
    let noise = responder_handshake(&mut transport, static_key, &authorized_keys).await?;
    transport.codec_mut().set_noise(noise);

    while let Some(request) = transport.next().await {
        println!("==========================");
        println!("Got request: {:?}", request);
        match request {
            Ok(request) => {
                match handle_request(&context, &mut transport, request).await {
                    Ok(_) => {
                        // continue
                    },
                    Err(e) => {
                        println!("{:?}", e);
                        break; // close this connection
                    },
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

async fn handle_request(context: &Context, transport: &mut Framed<TcpStream, NoiseMessageCodec>, request: BytesMut) -> Result<(), Box<dyn Error>> {
    let mut data = request.freeze();
    //let response = handle_request(&mut data).await?;
    //transport.send(response).await?;

    let mut msg = Message::deserialize(&mut data);
    println!("<- : {}", msg);

    match MessageType::try_from(msg.cmd) {
        Ok(MessageType::Ping) => {
            let msg = Message {
                cmd: MessageType::Pong as u32,
                payload: Bytes::copy_from_slice(b"Secret Pong"),
            };
            println!("-> : {}", msg);
            transport.send(msg.serialize()).await?;
        }
        Ok(MessageType::Pull) => {
            let pull_request = PullRequest::deserialize(&mut msg.payload);
            return handle_pull_request(&context.root_dir, transport, pull_request).await;
        }
        Ok(MessageType::Push) => {
            let push_request = PushRequest::deserialize(&mut msg.payload);
            return handle_push_request(&context.root_dir, transport, push_request).await;
        }
        _ => {
            return Err(Box::from(format!("unknown cmd: {}", msg.cmd)));
        }
    }

    Ok(())
}

/**
 * < handshake >
 * pull ->   
 *      <- file_header
 *      <- file_chunk
 *      <- file_chunk
 *      <- ...
 */
async fn pull_file(
    filepath: String,
    addr: &String,
    keyfile: Option<&std::path::PathBuf>,
) -> Result<(), Box<dyn Error>> {
    println!("keyfile: {:?}", keyfile);
    let keypair = match keyfile {
        Some(keyfile) => read_keypair_from_file(keyfile)?,
        None => gen_keypair()?
    }; 
    let static_key = &keypair.private;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut transport = Framed::new(stream, NoiseMessageCodec::new());

    let noise = initiator_handshake(&mut transport, static_key).await?;
    transport.codec_mut().set_noise(noise);

    let cmd = Message {
        cmd: MessageType::Pull as u32,
        payload: PullRequest::new(filepath).serialize(),
    };
    println!("<- : {}", cmd);
    transport.send(cmd.serialize()).await?;

    handle_pull_response(&mut transport, None).await?;

    Ok(())
}

/**
 * < handshake >
 * push(file_header) ->   
 *                   <- push_ack(or err)
 * file_chunk        ->
 * file_chunk        ->
 * ...               ->
 */
async fn push_file(
    local_filepath: String,
    remote_filepath: String,
    addr: &String,
    keyfile: Option<&std::path::PathBuf>,
) -> Result<(), Box<dyn Error>> {
    println!("keyfile: {:?}", keyfile);
    let mut remote_file = PathBuf::new();
    remote_file.push(&remote_filepath);
    let mut local_file = PathBuf::new();
    local_file.push(local_filepath);
    if !local_file.exists() {
        println!("Error: {:?} file is not exists!", local_file);
        return Ok(()); // TODO: Err()
    }
    let local_file_size = local_file.metadata().unwrap().len();
    let file_header = FileHeader {
        filename: local_file
            .file_name()
            .unwrap()
            .to_os_string()
            .into_string()
            .unwrap(),
        checksum: cal_file_checksum(local_file.as_path()).unwrap(),
        filesize: local_file_size
    };

    let keypair = match keyfile {
        Some(keyfile) => read_keypair_from_file(keyfile)?,
        None => gen_keypair()?
    }; 
    let static_key = &keypair.private;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut transport = Framed::new(stream, NoiseMessageCodec::new());

    let noise = initiator_handshake(&mut transport, static_key).await?;
    transport.codec_mut().set_noise(noise);

    let cmd = Message {
        cmd: MessageType::Push as u32,
        payload: PushRequest::new(file_header, remote_filepath).serialize(),
    };
    println!("-> : {}", cmd);
    transport.send(cmd.serialize()).await?;

    handle_push_response(&mut transport, local_file, local_file_size, remote_file).await?;

    Ok(())
}

// cargo test -- --nocapture client_test
#[tokio::test()]
async fn client_test() -> Result<(), Box<dyn Error>> {
    Ok(())
}
