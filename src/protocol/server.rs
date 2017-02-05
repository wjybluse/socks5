use std::net::{TcpListener,TcpStream,Ipv4Addr,SocketAddrV4,Shutdown};
use std::thread;
use std::io::prelude::*;
use super::common::SocksError;
use std::iter::FromIterator;
use super::constant;
use mioco;
#[derive(Debug,Clone)]
pub struct Server {
    host: String,
    port: u16,
}

impl Server{
    pub fn new(host: String,port: u16)->Server{
        Server{
            host: host,
            port: port,
        }
    }

    fn handshake(stream:&mut TcpStream)->Result<u8,SocksError>{
        //read 256 bit from tcp stream
        //let mut buffer: Vec<u8> = Vec::new();
        let mut buffer1: [u8;258] = [0;258];
        let size = try!(stream.read(&mut buffer1));
        //println!("buffer size is {}",size);
        let mut buffer: Vec<u8> = buffer1.to_vec();
        println!("buffer1 is {:?}",buffer);
        let version = buffer[0];
        if version != constant::SOCKS5{
            stream.write(&[0x01,0x00]);
            stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(0x01u32,"invalid version".to_string()))
        }
        let nmethod = buffer[1];
        if nmethod <=0u8{
            stream.write(&[0x01,0x00]);
            stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(0x01u32,"no method selected".to_string()))
        }
        if size < 2 {
            stream.write(&[0x01,0x00]);
            stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(0x01u32,"invalid size".to_string()))
        }
        let mut select_method = buffer[2];
        for value in buffer.drain(2..).take(nmethod as usize){
            if value == constant::NO_ACCEPTABLE{
                    stream.write(&[0x05,0xff]);
                    stream.shutdown(Shutdown::Both);
                    return Err(SocksError::CommonError(0x01u32,"invalid method".to_string()));
            }
            if value > select_method{
                //find prop
                select_method = value;
            }
        }
        println!("success.....");
        Ok(select_method)
    }

    fn authorization(stream:&mut TcpStream)->Result<(),SocksError>{
        println!("start authorization.....");
        let mut buffer1: [u8;1024] = [0;1024];
        //let mut buffer: Vec<u8> = Vec::with_capacity(1024);
        let total = try!(stream.read(&mut buffer1));
        let mut buffer: Vec<u8> = buffer1.to_vec();
        println!("handle new buffer {:?}",buffer);
        if buffer[0]!=0x01u8{
            return Err(SocksError::CommonError(0x01u32,"invalid version".to_string()))
        }
        //find username len
        let len = buffer[1] as usize;
        println!("find len {}",len);
        let username = String::from_utf8(buffer.drain(1..).take(len).collect());
        println!("after buffer is {:?}",buffer);
        let pass_len = buffer[len+2] as usize;
        let password = String::from_utf8(buffer.drain(len+3..total).collect());
        if let Ok(_user) = username{
            if let Ok(_pass) = password{
                if _user == "admin".to_string() && _pass == "admin".to_string(){
                    stream.write(&[0x00,0x00]);
                    return Ok(())
                }
            }
        }
        stream.write(&[0x01,0x00]);
        Err(SocksError::CommonError(0x01u32,"invalid username and password".to_string()))
    }

    fn handle_request(stream:&mut TcpStream)->Result<(),SocksError>{
        Ok(())
    }

}

pub trait Listener {
     fn add_hook<F>(&self,hook: F) where F: Fn(&mut TcpStream)->Result<(),SocksError>;
     fn bind(&self);
}

impl Listener for Server{
    fn add_hook<F>(&self,hook: F) where F: Fn(&mut TcpStream)->Result<(),SocksError>{
        //TODO  
    }
    fn bind(&self){
        let host = format!("{}:{}",self.host,self.port);
        let listener = TcpListener::bind(&*host).unwrap();
        loop {
                match listener.accept() {
                    Ok((mut stream,_))=>{
                        mioco::spawn(move ||{
                            let handshake=Server::handshake(&mut stream).unwrap();
                            //handshake ok
                            println!("hand shake method is {}",handshake);
                            stream.write(&[0x05,handshake]);
                            if handshake == constant::AUTHENTICATION{
                                Server::authorization(&mut stream).unwrap();
                            }else{
                            }
                        });
                    },
                    Err(e)=>{
                        println!("handle error {}",e);
                    }
                }
            }
    }
}


