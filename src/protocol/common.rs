use std::io;
use std::io::{Read, Write, ErrorKind};
use super::constant;
use regex::Regex;
// for handshake
pub struct ConnWrap<'a> {
    reader: &'a mut Read,
    writer: &'a mut Write,
}

impl<'a> ConnWrap<'a> {
    pub fn new(reader: &'a mut Read, writer: &'a mut Write) -> ConnWrap<'a> {
        ConnWrap {
            reader: reader,
            writer: writer,
        }
    }
    pub fn copy(&mut self) -> io::Result<usize> {
        let mut buffer: [u8; constant::DEFAULT_SIZE] = [0; constant::DEFAULT_SIZE];
        let mut write_len: usize = 0;
        loop {
            let len = match self.reader.read(&mut buffer) {
                Ok(0) => return Ok(write_len),
                Ok(len) => len,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let w = try!(self.writer.write(&buffer[..len]));
            assert_eq!(w, len);
            write_len += len;
        }
        Ok(write_len)
    }
}
#[derive(Debug)]
pub enum SocksError {
    // code and reason
    CommonError(usize, String),
}

impl From<io::Error> for SocksError {
    fn from(e: io::Error) -> SocksError {
        println!("error is {:?}", e);
        SocksError::CommonError(0x01, "IO Error".to_string())
    }
}

pub fn convert_port(arr: Vec<u8>) -> u16 {
    (arr[0] as u16) << 8 | (arr[1] as u16)
}

pub fn build_result(code: usize, msg: String) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![code as u8];
    vec.append(&mut msg.into_bytes());
    vec
}

pub fn is_match(domain: &str) -> bool {
    let pattern = Regex::new(constant::IPV4_PATTERN).unwrap();
    return pattern.is_match(&domain);
}