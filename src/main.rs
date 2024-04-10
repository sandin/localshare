mod codec;
mod commands;
mod keyring;
mod message;
mod noise;

use bytes::{Bytes, BytesMut};
use clap::{arg, Command};
use futures::SinkExt;
use std::error::Error;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::codec::NoiseMessageCodec;
use crate::commands::{handle_pull_request, handle_pull_response};
use crate::keyring::{read_keypair_from_file, write_keypair_to_file};
use crate::message::{Deserializable, FileHeader, Message, MessageType, PullRequest, Serializable};
use crate::noise::{gen_keypair, initiator_handshake, responder_handshake};

struct Context {
    keypair: snow::Keypair,
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
                        .required(true),
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
            let default_root_dir = "/".to_owned();
            let root_dir = matches.get_one::<String>("dir").unwrap_or(&default_root_dir);
            start_server(addr, keyfile, root_dir.to_string()).await?;
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

async fn start_server(addr: &String, keyfile: &std::path::PathBuf, root_dir: String) -> Result<(), Box<dyn Error>> {
    let keypair = read_keypair_from_file(keyfile)?;
    let context = Arc::new(Mutex::new(Context { keypair, root_dir }));

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
    println!("-> : {}", msg);

    match MessageType::try_from(msg.cmd) {
        Ok(MessageType::Ping) => {
            let msg = Message {
                cmd: MessageType::Pong as u32,
                payload: Bytes::copy_from_slice(b"Secret Pong"),
            };
            println!("Send msg: {}", msg);
            transport.send(msg.serialize()).await?;
        }
        Ok(MessageType::Pull) => {
            let pull_request = PullRequest::deserialize(&mut msg.payload);
            return handle_pull_request(&context.root_dir, transport, pull_request).await;
        }
        Ok(MessageType::Push) => {
            // TODO
        }
        _ => {
            return Err(Box::from(format!("unknown cmd: {}", msg.cmd)));
        }
    }

    Ok(())
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
    println!("<- : {}", cmd);
    transport.send(cmd.serialize()).await?;

    handle_pull_response(&mut transport).await?;

    Ok(())
}

// cargo test -- --nocapture client_test
#[tokio::test()]
async fn client_test() -> Result<(), Box<dyn Error>> {
    Ok(())
}
