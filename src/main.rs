mod command;

use bytes::{Bytes, BytesMut};
use clap::{arg, Command};
use futures::SinkExt;
use std::convert::TryFrom;
use std::{env, error::Error, fmt, io};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::command::{Command as Cmd, CommandType};

static SECRET: &[u8] = b"i don't care for fidget spinners";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("localshare")
        .bin_name("localshare")
        .subcommand_required(true)
        .subcommand(
            Command::new("server").about("start server").arg(
                arg!(<ADDR> "the server address")
                    .required(false)
                    .default_value("0.0.0.0:8080"),
            ),
        )
        .subcommand(
            Command::new("client")
                .about("client")
                .arg(arg!(<ADDR> "the server address"))
                .arg_required_else_help(true),
        );
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("server", matches)) => {
            let addr = matches.get_one::<String>("ADDR").expect("required");
            start_server(addr).await?;
        }
        Some(("client", matches)) => {
            let addr = matches.get_one::<String>("ADDR").expect("required");
            start_client(addr).await?;
        }
        _ => unreachable!("clap should ensure we don't get here"),
    };

    Ok(())
}

async fn start_server(addr: &String) -> Result<(), Box<dyn Error>> {
    let server = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    loop {
        let (stream, _) = server.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                println!("failed to process connection; error = {}", e);
            }
        });
    }
}

async fn handle_client(stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let codec = LengthDelimitedCodec::builder().little_endian().new_codec();
    let mut transport = Framed::new(stream, codec);

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                println!("Got request: {:?}", request);
                let response = handle_request(request).await?;
                println!("Send response: {:?}", response);
                transport.send(response).await?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

async fn handle_request(req: BytesMut) -> Result<Bytes, Box<dyn Error>> {
    let mut data = req.freeze();
    let cmd = Cmd::new(&mut data);
    println!("Got cmd: {:?}", cmd);

    let mut buf = vec![0u8; 65535];
    let builder: snow::Builder<'_> =
        snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let static_key = builder.generate_keypair().unwrap().private;
    let mut noise = builder
        .local_private_key(&static_key)
        .psk(3, SECRET)
        .build_responder()
        .unwrap();
    match CommandType::try_from(cmd.cmd) {
        Ok(CommandType::Handshake) => {
            // TODO
            noise.read_message(&cmd.payload, &mut buf)?;
        }
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

async fn start_client(addr: &String) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let codec = LengthDelimitedCodec::builder().little_endian().new_codec();
    let mut transport = Framed::new(stream, codec);

    let mut buf = vec![0u8; 65535];
    let builder: snow::Builder<'_> =
        snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let static_key = builder.generate_keypair().unwrap().private;
    let mut noise = builder
        .local_private_key(&static_key)
        .psk(3, SECRET)
        .build_initiator()
        .unwrap();

    let len = noise.write_message(&[], &mut buf).unwrap();
    let cmd = Cmd {
        cmd: CommandType::Handshake as u32,
        payload: Bytes::copy_from_slice(&buf[..len]),
    };
    transport.send(cmd.as_bytes()).await.unwrap();

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                println!("Got request: {:?}", request);
                let mut data = request.freeze();
                let cmd = Cmd::new(&mut data);
                println!("Got cmd: {:?}", cmd);
                if cmd.cmd == CommandType::Handshake as u32 {
                    noise.read_message(&data, &mut buf).unwrap();

                    let len = noise.write_message(&[], &mut buf).unwrap();
                    let cmd = Cmd {
                        cmd: CommandType::Handshake1 as u32,
                        payload: Bytes::copy_from_slice(&buf[..len]),
                    };
                    transport.send(cmd.as_bytes()).await.unwrap();
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
