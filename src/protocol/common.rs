use std::io;
//for handshake

#[derive(Debug)]
pub enum SocksError{
   //code and reason
   CommonError(usize,String),
}

impl  From<io::Error> for SocksError{
    fn from(e: io::Error) -> SocksError {
        SocksError::CommonError(0x01,"IO Error".to_string())
    }
}

pub fn convert_port(arr: Vec<u8>)->u16{
     (arr[0] as u16) << 8 | (arr[1] as u16)
}

pub fn build_result(code: usize,msg: String)->Vec<u8>{
    let mut vec: Vec<u8> = vec![code as u8];
    vec.append(&mut msg.into_bytes());
    vec
}
