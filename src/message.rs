use crate::file_chunk::cal_file_checksum;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use std::mem::size_of;
use std::path::Path;

#[derive(TryFromPrimitive)]
#[repr(u32)]
pub enum MessageType {
    Handshake = 1,
    Handshake1 = 2,
    Ping = 3,
    Pong = 4,
    Push = 5,
    Pull = 6,
    Text = 7,
    FileHeader = 8,
    FileChunk = 9,
}

/// Serializable (struct -> Bytes)
pub trait Serializable {
    // Serialize from struct to Bytes
    fn serialize(&self) -> Bytes;
}

/// Deserializable (Bytes -> struct)
pub trait Deserializable<T> {
    // Deserialize from Bytes to struct
    fn deserialize(bytes: &mut Bytes) -> T;
}

#[derive(Debug, Clone)]
pub struct Message {
    pub cmd: u32,
    pub payload: Bytes,
}

impl Serializable for Message {
    fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(size_of::<u32>() + self.payload.len());
        buf.put_u32_le(self.cmd);
        buf.put_slice(&self.payload);
        return buf.freeze();
    }
}

impl Deserializable<Message> for Message {
    fn deserialize(bytes: &mut Bytes) -> Message {
        Message {
            cmd: bytes.get_u32_le(),
            payload: bytes.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct PullRequest {
    pub filepath: String,
}

impl PullRequest {
    pub fn new(filepath: String) -> Self {
        PullRequest { filepath }
    }
}

impl Serializable for PullRequest {
    fn serialize(&self) -> Bytes {
        Bytes::copy_from_slice(&bincode::serialize(&self).unwrap())
        /*
        let bytes = self.filepath.as_bytes();
        let mut buf = BytesMut::with_capacity(size_of::<u32>() + bytes.len());
        buf.put_u32_le(bytes.len() as u32);
        buf.put_slice(&bytes);
        return buf.freeze();
        */
    }
}

impl Deserializable<PullRequest> for PullRequest {
    fn deserialize(bytes: &mut Bytes) -> Self {
        bincode::deserialize(&bytes.to_vec()).unwrap()
        /*
        let str_len = bytes.get_u32_le() as usize;
        let str_data = bytes.slice(0..str_len);
        PullRequest {
            filepath: String::from_utf8(str_data.to_vec()).unwrap()
        }
        */
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct FileHeader {
    pub filename: String,
    pub checksum: String,
    pub filesize: u64,
}

impl FileHeader {
    pub fn new(filepath: &Path) -> Self {
        FileHeader {
            filename: filepath
                .file_name()
                .unwrap()
                .to_os_string()
                .into_string()
                .unwrap(),
            checksum: cal_file_checksum(filepath).unwrap(),
            filesize: filepath.metadata().unwrap().len(),
        }
    }
}

impl Serializable for FileHeader {
    fn serialize(&self) -> Bytes {
        Bytes::copy_from_slice(&bincode::serialize(&self).unwrap())
    }
}

impl Deserializable<FileHeader> for FileHeader {
    fn deserialize(bytes: &mut Bytes) -> Self {
        bincode::deserialize(&bytes.to_vec()).unwrap()
    }
}
