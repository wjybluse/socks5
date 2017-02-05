use std::io;
//for handshake

#[derive(Debug)]
pub enum SocksError{
   //code and reason
   CommonError(u32,String),
   IOError(u32,String),
}

impl  From<io::Error> for SocksError{
    fn from(e: io::Error) -> SocksError {
        SocksError::IOError(0x01u32,"IO Error".to_string())
    }
}