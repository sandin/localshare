use num_enum::TryFromPrimitive;
use bytes::{Bytes, Buf, BytesMut, BufMut};

#[derive(TryFromPrimitive)]
#[repr(u32)]
pub enum CommandType {
    Handshake = 1,
    Handshake1 = 2,
    Push = 3,
    Pull = 4,
}

#[derive(Debug, Clone)]
pub struct Command {
    pub cmd: u32, 
    pub payload: Bytes,
}

impl Command {

    pub fn new(bytes: &mut Bytes) -> Command {
        Command {
            cmd: bytes.get_u32_le(),
            payload: bytes.clone()
        }
    }

    pub fn as_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1024);
        buf.put_u32_le(self.cmd);
        buf.put_slice(&self.payload.slice(0..self.payload.len()));
        return buf.freeze();
    }

}