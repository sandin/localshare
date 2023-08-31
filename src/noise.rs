use bytes::Bytes;
use futures::SinkExt;
use lazy_static::lazy_static;
use snow::{params::NoiseParams, Keypair, TransportState};
use std::error::Error;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::codec::NoiseMessageCodec;
use crate::keyring::serialize_key;
use crate::message::{Deserializable, Message, MessageType, Serializable};

static SECRET: &[u8] = &[
    0xb5, 0x34, 0x9c, 0x8f, 0xea, 0x4f, 0xb1, 0x0d, 0xbc, 0xe3, 0x38, 0xe4, 0x35, 0x41, 0x7a, 0x8d,
    0xb8, 0x21, 0x68, 0x69, 0xf1, 0xa1, 0xa8, 0xcd, 0x08, 0xc5, 0x03, 0xab, 0xba, 0x1e, 0xfc, 0x14,
];
lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

pub fn gen_keypair() -> Result<Keypair, Box<dyn Error>> {
    let builder: snow::Builder<'_> = snow::Builder::new(PARAMS.clone());
    Ok(builder.generate_keypair().unwrap())
}

pub async fn responder_handshake(
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
    static_key: &Vec<u8>,
) -> Result<TransportState, Box<dyn Error>> {
    let builder: snow::Builder<'_> = snow::Builder::new(PARAMS.clone());
    let mut handshake = builder
        .local_private_key(static_key)
        .psk(3, SECRET)
        .build_responder()
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let noise;
    loop {
        if handshake.is_handshake_finished() {
            println!("handshake complete");
            noise = handshake.into_transport_mode().unwrap();
            break;
        }
        let request = transport.next().await.unwrap()?;
        let mut data = request.freeze();
        let msg = Message::deserialize(&mut data);
        if msg.cmd == MessageType::Handshake as u32 {
            println!("<- e: {:?}", msg.payload);
            handshake.read_message(&msg.payload, &mut buf)?;

            let len = handshake.write_message(&[], &mut buf).unwrap();
            let cmd = Message {
                cmd: MessageType::Handshake as u32,
                payload: Bytes::copy_from_slice(&buf[..len]),
            };
            transport.send(cmd.serialize()).await?;
            println!("-> e, ee, s, es: {:?}", cmd.payload);
        } else if msg.cmd == MessageType::Handshake1 as u32 {
            println!("<- s, se: {:?}", msg.payload);
            handshake.read_message(&msg.payload, &mut buf)?;

            let s = serialize_key(handshake.get_remote_static().unwrap());
            println!("remote static key: {}", s);
        }
    }

    Ok(noise)
}

pub async fn initiator_handshake(
    transport: &mut Framed<TcpStream, NoiseMessageCodec>,
    static_key: &Vec<u8>,
) -> Result<TransportState, Box<dyn Error>> {
    let builder: snow::Builder<'_> = snow::Builder::new(PARAMS.clone());
    let mut handshake = builder
        .local_private_key(static_key)
        .psk(3, SECRET)
        .build_initiator()
        .unwrap();

    let mut buf = vec![0u8; 65535];

    let len = handshake.write_message(&[], &mut buf).unwrap();
    let cmd = Message {
        cmd: MessageType::Handshake as u32,
        payload: Bytes::copy_from_slice(&buf[..len]),
    };
    transport.send(cmd.serialize()).await.unwrap();
    println!("-> e: {:?}", cmd.payload);

    let noise;
    loop {
        if handshake.is_handshake_finished() {
            println!("handshake complete");
            noise = handshake.into_transport_mode().unwrap();
            break;
        }
        let request = transport.next().await.unwrap()?;
        let mut data = request.freeze();
        let cmd = Message::deserialize(&mut data);
        if cmd.cmd == MessageType::Handshake as u32 {
            println!("<- e, ee, s, es: {:?}", cmd.payload);
            handshake.read_message(&cmd.payload, &mut buf)?;

            let s = serialize_key(handshake.get_remote_static().unwrap());
            println!("remote static key: {}", s);

            let len = handshake.write_message(&[], &mut buf).unwrap();
            let cmd = Message {
                cmd: MessageType::Handshake1 as u32,
                payload: Bytes::copy_from_slice(&buf[..len]),
            };
            transport.send(cmd.serialize()).await?;
            println!("-> s, se: {:?}", cmd.payload);
        }
    }

    Ok(noise)
}
