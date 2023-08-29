mod command;

use std::{env, error::Error, fmt, io};
use std::convert::TryFrom;
use bytes::{Bytes, BytesMut};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use futures::SinkExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::command::{Command, CommandType};

static SECRET: &[u8] = b"lds";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>  {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
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
    let cmd = Command::new(&mut data);
    println!("Got cmd: {:?}", cmd);

    let mut buf = vec![0u8; 65535];
    let mut noise = snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap()).build_initiator().unwrap(); // TODO
    match CommandType::try_from(cmd.cmd) {
        Ok(CommandType::Handshake) => {
            // TODO
            noise.read_message(&cmd.payload, &mut buf)?;
        },
        Ok(CommandType::Push) => {
            // TODO
        },
        Ok(CommandType::Pull) => {
            // TODO
        },
        _ => {
            println!("unknown cmd: {}", cmd.cmd);
        }
    }
    Ok(data)
}

// cargo test -- --nocapture client_test
#[tokio::test()]
async fn client_test() -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();
    let codec = LengthDelimitedCodec::builder().little_endian().new_codec();
    let mut transport = Framed::new(stream, codec);

    let mut buf = vec![0u8; 65535];
    let builder: snow::Builder<'_> = snow::Builder::new("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let static_key = builder.generate_keypair().unwrap().private;
    let mut noise =
        builder.local_private_key(&static_key).psk(3, SECRET).build_initiator().unwrap();

    let len = noise.write_message(&[], &mut buf).unwrap();
    let cmd = Command {
        cmd: CommandType::Handshake as u32,
        payload: Bytes::copy_from_slice(&buf[..len]),
    };
    transport.send(cmd.as_bytes()).await.unwrap();

    while let Some(request) = transport.next().await {
        match request {
            Ok(request) => {
                println!("Got request: {:?}", request);
                let mut data = request.freeze();
                let cmd = Command::new(&mut data);
                println!("Got cmd: {:?}", cmd);
                if cmd.cmd == CommandType::Handshake as u32 {
                    noise.read_message(&data, &mut buf).unwrap();

                    let len = noise.write_message(&[], &mut buf).unwrap();
                    let cmd = Command {
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