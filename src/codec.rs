use bytes::{Bytes, BytesMut};
use snow::TransportState;
use std::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

// The state of decode
#[derive(Debug, Clone, Copy)]
enum DecodeState {
    // unencrypted message, only used for handshake stage
    Plaintext,

    // encrypted message, used for transport stage
    Cyphertext,
}

/// A codec for noise encrypted message
pub struct NoiseMessageCodec {
    // noise after handshake
    noise: Option<TransportState>,

    // inner codec
    inner: LengthDelimitedCodec,

    // buffer for encode(encrypted) message
    encode_buffer: Vec<u8>,

    // buffer for decode(decrypted) message
    decode_buffer: Vec<u8>,

    // decode state(cyphertext or plaintext)
    state: DecodeState,
}

impl NoiseMessageCodec {
    /// constructor
    pub fn new() -> Self {
        NoiseMessageCodec {
            noise: None,
            inner: LengthDelimitedCodec::builder().little_endian().new_codec(),
            encode_buffer: vec![0u8; 65535],
            decode_buffer: vec![0u8; 65535],
            state: DecodeState::Plaintext,
        }
    }

    /// Set noise and switch to encrypted transmission mode
    pub fn set_noise(&mut self, noise: TransportState) {
        self.noise = Some(noise);
        self.state = DecodeState::Cyphertext;
    }
}

impl Default for NoiseMessageCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for NoiseMessageCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            DecodeState::Cyphertext => {
                // Decrypt messages first in encrypted transmission mode
                if let Some(noise) = &mut self.noise {
                    let mut item = BytesMut::with_capacity(0);
                    for chunk in src.chunks(self.decode_buffer.len()) {
                        match noise.read_message(&chunk, &mut self.decode_buffer) {
                            Ok(len) => {
                                println!("Decode cyphertext: {:?}", Bytes::copy_from_slice(chunk));
                                item.extend_from_slice(&self.decode_buffer[..len]);
                                println!("Decode plaintext: {:?}", item);
                            }
                            Err(e) => {
                                break;
                            }
                        }
                    }
                    return self.inner.decode(&mut item);
                } else {
                    return self.inner.decode(src);
                }
            }
            DecodeState::Plaintext => {
                return self.inner.decode(src);
            }
        }
    }
}

impl Encoder<Bytes> for NoiseMessageCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self.state {
            DecodeState::Cyphertext => {
                match self.inner.encode(item, dst) {
                    Ok(r) => {
                        if let Some(noise) = &mut self.noise {
                            let mut cyphertext = BytesMut::with_capacity(0);
                            for chunk in dst.chunks(self.encode_buffer.len()) {
                                println!("Encode plaintext: {:?}", Bytes::copy_from_slice(chunk));
                                let len = noise
                                    .write_message(&chunk, &mut self.encode_buffer)
                                    .unwrap();
                                cyphertext.extend_from_slice(&self.encode_buffer[..len]);
                                println!("Encode cyphertext: {:?}", cyphertext);
                            }

                            unsafe {
                                dst.set_len(cyphertext.len());
                            } // TODO: unsafe?
                            dst.copy_from_slice(&cyphertext);
                        }
                        Ok(r)
                    }
                    Err(e) => Err(e),
                }
            }
            DecodeState::Plaintext => {
                return self.inner.encode(item, dst);
            }
        }
    }
}
