use std::io;
use std::io::{Read, Write, ErrorKind};
use super::constant;
// for handshake

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

pub fn copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> io::Result<u64>
    where R: Read,
          W: Write
{
    let mut buffer: [u8; constant::DEFAULT_SIZE] = [0; constant::DEFAULT_SIZE];
    let mut write_len: u64 = 0;
    loop {
        let len = match reader.read(&mut buffer) {
            Ok(0) => return Ok(write_len),
            Ok(len) => len,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let w = try!(writer.write(&buffer[..len]));
        assert_eq!(w, len);
        write_len += len as u64;
    }
    Ok(write_len)
}
