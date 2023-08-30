mod command;
mod keyring;

use base64ct::{Base64, Encoding};
use bytes::{Bytes, BytesMut};
use clap::{arg, Command};
use futures::SinkExt;
use std::convert::TryFrom;
use std::sync::Arc;
use std::{env, error::Error, fmt, io};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::command::{Command as Cmd, CommandType};
use crate::keyring::{read_keypair_from_file, write_keypair_to_file};

static SECRET: &[u8] = b"i don't care for fidget spinners";

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
            gen_keypair(output).await?;
        }
        _ => unreachable!("clap should ensure we don't get here"),
    };

    Ok(())
}

async fn gen_keypair(output: &std::path::PathBuf) -> Result<(), Box<dyn Error>> {
    let builder: snow::Builder<'_> =
        snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let keypair = builder.generate_keypair().unwrap();

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
    let mut transport = Framed::new(stream, codec);

    // handshake
    let builder: snow::Builder<'_> =
        snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let context = context.lock().await;
    let static_key = &context.keypair.private;
    let mut handshake = builder
        .local_private_key(static_key)
        .psk(3, SECRET)
        .build_responder()
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let mut noise;// : Option<snow::TransportState> = None;
    loop {
        if handshake.is_handshake_finished() {
            println!("handshake complete");
            //noise1 = Some(noise.into_transport_mode().unwrap());
            noise = handshake.into_transport_mode().unwrap();
            break;
        }
        let request = transport.next().await.unwrap()?;
        let mut data = request.freeze();
        let cmd = Cmd::new(&mut data); 
        if cmd.cmd == CommandType::Handshake as u32 {
            println!("<- e: {:?}", cmd.payload);
            handshake.read_message(&cmd.payload, &mut buf)?;

            let len = handshake.write_message(&[], &mut buf).unwrap();
            let cmd = Cmd {
                cmd: CommandType::Handshake as u32,
                payload: Bytes::copy_from_slice(&buf[..len]),
            };
            transport.send(cmd.as_bytes()).await?;
            println!("<- e, ee, s, es: {:?}", cmd.payload);
        } else if cmd.cmd == CommandType::Handshake1 as u32 {
            println!("<- s, se: {:?}", cmd.payload);
            handshake.read_message(&cmd.payload, &mut buf)?;
        }
    }

    let cmd = Cmd {
        cmd: CommandType::Handshake1 as u32,
        payload: Bytes::new(),
    };
    let len = noise.write_message(&cmd.as_bytes(), &mut buf).unwrap();
    let data = Bytes::copy_from_slice(&buf[..len]);
    transport.send(data).await?;
    println!("send secured message");

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                println!("Got request: {:?}", request);
                let response = handle_request(&mut noise, request).await?;
                println!("Send response: {:?}", response);
                transport.send(response).await?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

async fn handle_request(
    noise: &mut snow::TransportState,
    req: BytesMut,
) -> Result<Bytes, Box<dyn Error>> {
    let mut data = req.freeze();
    let cmd = Cmd::new(&mut data);
    //println!("Got cmd: {:?}", cmd);

    let mut buf = vec![0u8; 65535];

    match CommandType::try_from(cmd.cmd) {
        Ok(CommandType::Push) => {
            // TODO
        }
        Ok(CommandType::Pull) => {
            // TODO
        }
        _ => {
            println!("unknown cmd: {}", cmd.cmd);
        }
    }
    Ok(data)
}

async fn start_client(addr: &String, keyfile: &std::path::PathBuf) -> Result<(), Box<dyn Error>> {
    let keypair = read_keypair_from_file(keyfile)?;
    let static_key = &keypair.private;

    let stream = TcpStream::connect(addr).await.unwrap();
    let codec = LengthDelimitedCodec::builder().little_endian().new_codec();
    let mut transport = Framed::new(stream, codec);

    let mut buf = vec![0u8; 65535];
    let builder: snow::Builder<'_> =
        snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let mut handshake = builder
        .local_private_key(static_key)
        .psk(3, SECRET)
        .build_initiator()
        .unwrap();

    // send handshake
    let len = handshake.write_message(&[], &mut buf).unwrap();
    let cmd = Cmd {
        cmd: CommandType::Handshake as u32,
        payload: Bytes::copy_from_slice(&buf[..len]),
    };
    transport.send(cmd.as_bytes()).await.unwrap();
    println!("-> e: {:?}", cmd.payload);

    // recv handshake
    let request = transport.next().await.unwrap()?;
    let mut data = request.freeze();
    let cmd = Cmd::new(&mut data);
    if cmd.cmd != CommandType::Handshake as u32 {
        return Err(Box::from("invalid cmd"));
    }
    println!("<- e, ee, s, es: {:?}", cmd.payload);
    handshake.read_message(&data, &mut buf).unwrap();

    // send handshake1
    let len = handshake.write_message(&[], &mut buf).unwrap();
    let cmd = Cmd {
        cmd: CommandType::Handshake1 as u32,
        payload: Bytes::copy_from_slice(&buf[..len]),
    };
    transport.send(cmd.as_bytes()).await.unwrap();
    println!("-> s, se: {:?}", cmd.payload);

    if !handshake.is_handshake_finished() {
        return Err(Box::from("invalid state"));
    }
    let mut noise = handshake.into_transport_mode().unwrap();

    // recv handshake1(secured message)
    let request = transport.next().await.unwrap()?;
    let mut data = request.freeze();
    println!("Got secured message: {:?}", data);
    let len = noise.read_message(&data, &mut buf).unwrap();
    data = Bytes::copy_from_slice(&buf[..len]);
    println!("Decode secured message: {:?}", data);
    let cmd = Cmd::new(&mut data);
    println!("Parse secured message: {:?}", cmd);
    if cmd.cmd != CommandType::Handshake1 as u32 {
        return Err(Box::from("invalid cmd, expect Handshake1"));
    }

    // secureline
    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                println!("Got request: {:?}", request);
                let mut data = request.freeze();
                let cmd = Cmd::new(&mut data);
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
