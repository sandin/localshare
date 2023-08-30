use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive)]
#[repr(u32)]
pub enum MessageType {
    Handshake = 1,
    Handshake1 = 2,
    Ping = 3,
    Pong = 4,
    Push = 5,
    Pull = 6,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub cmd: u32,
    pub payload: Bytes,
}

impl Message {
    pub fn new(bytes: &mut Bytes) -> Message {
        Message {
            cmd: bytes.get_u32_le(),
            payload: bytes.clone(),
        }
    }

    pub fn as_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1024);
        buf.put_u32_le(self.cmd);
        buf.put_slice(&self.payload.slice(0..self.payload.len()));
        return buf.freeze();
    }
}
