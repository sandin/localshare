mod message;
mod keyring;
mod noise;

use bytes::Bytes;
use clap::{arg, Command};
use futures::SinkExt;
use std::error::Error;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::message::{Message, MessageType};
use crate::keyring::{read_keypair_from_file, write_keypair_to_file};
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
            Command::new("client")
                .about("start client")
                .arg(arg!(<ADDR> "the server address"))
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
        Some(("client", matches)) => {
            let addr = matches.get_one::<String>("ADDR").expect("required");
            let keyfile = matches
                .get_one::<std::path::PathBuf>("key")
                .expect("required");
            start_client(addr, keyfile).await?;
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
    let codec = LengthDelimitedCodec::builder().little_endian().new_codec();
    let mut transport: Framed<TcpStream, LengthDelimitedCodec> = Framed::new(stream, codec);
    let mut buf = vec![0u8; 65535];

    let context = context.lock().await;
    let static_key = &context.keypair.private;
    let mut noise = responder_handshake(&mut transport, static_key).await?;

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let mut data = request.freeze();
                println!("Got message(cyphertext): {:?}", data);
                let len = noise.read_message(&data, &mut buf).unwrap();
                data = Bytes::copy_from_slice(&buf[..len]);
                println!("Got message(plaintext): {:?}", data);

                let response = handle_request(&mut data).await?;
                println!("Send message(plaintext): {:?}", response);
                let len = noise.write_message(&response, &mut buf).unwrap();
                let data = Bytes::copy_from_slice(&buf[..len]);
                println!("Send message(cyphertext): {:?}", data);
                transport.send(data).await?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

async fn handle_request(data: &mut Bytes) -> Result<Bytes, Box<dyn Error>> {
    let msg = Message::new(data);
    println!("Got cmd: {:?}", msg);

    match MessageType::try_from(msg.cmd) {
        Ok(MessageType::Ping) => {
            let resp = Message {
                cmd: MessageType::Pong as u32,
                payload: Bytes::copy_from_slice(b"Secret Message"),
            };
            return Ok(resp.as_bytes());
        }
        Ok(MessageType::Push) => {
            // TODO
        }
        Ok(MessageType::Pull) => {
            // TODO
        }
        _ => {
            println!("unknown cmd: {}", msg.cmd);
        }
    }
    Ok(Bytes::new())
}

async fn start_client(addr: &String, keyfile: &std::path::PathBuf) -> Result<(), Box<dyn Error>> {
    let keypair = read_keypair_from_file(keyfile)?;
    let static_key = &keypair.private;

    let stream = TcpStream::connect(addr).await.unwrap();
    let codec = LengthDelimitedCodec::builder().little_endian().new_codec();
    let mut transport = Framed::new(stream, codec);

    let mut buf = vec![0u8; 65535];

    let mut noise = initiator_handshake(&mut transport, static_key).await?;

    let cmd = Message {
        cmd: MessageType::Ping as u32,
        payload: Bytes::copy_from_slice(b"Secret Message"),
    };
    let len = noise.write_message(&cmd.as_bytes(), &mut buf).unwrap();
    let data = Bytes::copy_from_slice(&buf[..len]);
    transport.send(data).await?;
    println!("send the first secured message(PING)");

    // secureline
    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                let mut data = request.freeze();
                println!("Got message(cyphertext): {:?}", data);
                let len = noise.read_message(&data, &mut buf).unwrap();
                data = Bytes::copy_from_slice(&buf[..len]);
                println!("Got message(plaintext): {:?}", data);

                let cmd = Message::new(&mut data);
                println!("Got cmd: {:?}", cmd);
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
