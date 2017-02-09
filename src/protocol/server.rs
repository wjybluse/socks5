use std::net::{TcpListener, TcpStream, Ipv4Addr, Ipv6Addr, SocketAddrV4, Shutdown, SocketAddr};
use std::thread;
use std::io::prelude::*;
use std::io::copy;
use super::common::{SocksError, convert_port, build_result};
use std::iter::FromIterator;
use super::constant;
use std::time::Duration;
use mioco;
#[derive(Debug,Clone)]
pub struct Server {
    host: String,
    port: u16,
}

impl Server {
    pub fn new(host: String, port: u16) -> Server {
        Server {
            host: host,
            port: port,
        }
    }

    fn handshake(stream: &mut TcpStream) -> Result<u8, SocksError> {
        // read 256 bit from tcp stream
        // let mut buffer: Vec<u8> = Vec::new();
        let mut buffer1: [u8; 258] = [0; 258];
        let size = try!(stream.read(&mut buffer1));
        // println!("buffer size is {}",size);
        let mut buffer: Vec<u8> = buffer1.to_vec();
        let version = buffer[0];
        if version != constant::SOCKS5 {
            // let msg = "invalid socks version".to_string().into_vec();
            stream.write(&build_result(constant::COMMON_ERR, "invalid socks version".to_string()));
            stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(constant::COMMON_ERR,
                                               "invalid version".to_string()));
        }
        let nmethod = buffer[1];
        if nmethod <= 0x0u8 {
            stream.write(&build_result(constant::COMMON_ERR,"invalid socks method len".to_string()));
            stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(constant::COMMON_ERR,
                                               "no method selected".to_string()));
        }
        if size < 2 {
            stream.write(&build_result(constant::COMMON_ERR, "invalid buffer stream".to_string()));
            stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(constant::COMMON_ERR, "invalid size".to_string()));
        }
        let mut select_method = buffer[2];
        for value in buffer.drain(2..).take(nmethod as usize) {
            if value == constant::NO_ACCEPTABLE {
                stream.write(&[0x05, 0xff]);
                stream.shutdown(Shutdown::Both);
                return Err(SocksError::CommonError(constant::COMMON_ERR,
                                                   "invalid method".to_string()));
            }
            if value > select_method {
                // find prop
                select_method = value;
            }
        }
        Ok(select_method)
    }

    fn authorization(stream: &mut TcpStream) -> Result<(), SocksError> {
        let mut buffer1: [u8; 1024] = [0; 1024];
        // let mut buffer: Vec<u8> = Vec::with_capacity(1024);
        let total = try!(stream.read(&mut buffer1));
        let mut buffer: Vec<u8> = buffer1.to_vec();
        if buffer[0] != 0x01u8 {
            return Err(SocksError::CommonError(constant::COMMON_ERR,
                                               "invalid version".to_string()));
        }
        // find username len
        let len = buffer[1] as usize;
        let pass_len = buffer[len + 2] as usize;
        let password: String =
            String::from_utf8(buffer.drain((len + 3)..).take(pass_len).collect()).unwrap();
        let username: String = String::from_utf8(buffer.drain(2..).take(len).collect()).unwrap();
        // println!("username is {},password is {},", username, password);
        if username == "admin" && password == "admin" {
            stream.write(&[0x00, 0x00]);
            Ok(())
        } else {
            stream.write(&[0x01, 0x00]);
            Err(SocksError::CommonError(constant::COMMON_ERR,
                                        "invalid username and password".to_string()))
        }

    }

    fn handle_request(stream: &mut TcpStream) -> Result<(), SocksError> {
        // read fix buffer
        let fix_len = constant::VER + constant::CMD + constant::RSV + constant::ATYP; //read known length from stream
        let mut _buffer: [u8; 1024] = [0; 1024];
        let size = try!(stream.read(&mut _buffer));
        let mut buffer_vec: Vec<u8> = _buffer.to_vec();
        if size < fix_len {
            stream.write(&build_result(constant::COMMON_ERR, "buffer size is err".to_string()));
            return Err(SocksError::CommonError(constant::COMMON_ERR, "invalid len".to_string()));
        }
        if buffer_vec[0] != constant::SOCKS5 {
            stream.write(&build_result(constant::COMMON_ERR, "socks version is err".to_string()));
            return Err(SocksError::CommonError(constant::COMMON_ERR,
                                               "invalid version".to_string()));
        }
        let cmd = buffer_vec[1];

        // get ip stream all
        // clone buffer to client
        // fuck ????
        let mut _domain: Vec<u8> = buffer_vec.drain(3..).take(size - 3).collect();
        match cmd {
            constant::BIND => {
                let mut s = Server::handle_bind(&mut _domain).unwrap();
                Ok(())
            }
            constant::CONNECT => {
                let mut _stream_clone = stream.try_clone().unwrap();
                let s = Server::handle_connect(&mut _domain, &mut _stream_clone).unwrap();

                let mut client_reader = stream.try_clone().unwrap();
                // clone s stream
                let mut server_writer = s.try_clone().unwrap();
                // move
                let rh = mioco::spawn(move || {
                    copy(&mut client_reader, &mut server_writer).unwrap();
                    client_reader.shutdown(Shutdown::Read);
                    server_writer.shutdown(Shutdown::Write);
                });

                let mut client_writer = stream.try_clone().unwrap();
                // clone s stream
                let mut server_reader = s.try_clone().unwrap();
                let wh = mioco::spawn(move || {
                    copy(&mut server_reader, &mut client_writer).unwrap();
                    server_reader.shutdown(Shutdown::Read);
                    client_writer.shutdown(Shutdown::Write);
                });
                rh.join().unwrap();
                wh.join().unwrap();
                Ok(())
            }
            constant::UDP => {
                let mut s = Server::handle_udp(&mut _domain).unwrap();
                Ok(())
            }
            _ => {
                stream.write(&build_result(constant::CMD_NOT_SUPPORT_ERR,
                                           "command not support".to_string()));
                Err(SocksError::CommonError(constant::CMD_NOT_SUPPORT_ERR,
                                            "Command not supported".to_string()))
            }
        }

    }

    fn handle_bind(domain: &mut Vec<u8>) -> Result<TcpStream, SocksError> {
        let start = domain.len() - 2;
        let port = convert_port(domain.drain(start..).take(2).collect());
        let address = String::from_utf8(domain.drain(0..).take(start).collect()).unwrap();
        let host = format!("{}:{}", address, port);
        let mut stream = try!(TcpStream::connect(&*host));
        Ok(stream)
    }

    fn handle_connect(domain: &mut Vec<u8>,
                      stream: &mut TcpStream)
                      -> Result<TcpStream, SocksError> {
        let ip_type = domain[0];
        // default is ipv4
        let mut ip_len = constant::IPV4_LEN;
        let mut start = 1;
        match ip_type {
            constant::IPV4 => ip_len = constant::IPV4_LEN + 2,
            // the last is port size
            constant::DOMAIN => {
                ip_len = domain[1] as usize + 2; //address + port
                start = 2;
            }//this is domain
            constant::IPV6 => ip_len = constant::IPV6_LEN + 2,
            _ => {
                stream.write(&mut [0x05,
                                   constant::ADDRESS_TYPE_NOT_SUPPORT_ERR as u8,
                                   0x00,
                                   0x01,
                                   127,
                                   0x00,
                                   0x00,
                                   0x01,
                                   0x00,
                                   0x00]);
                stream.shutdown(Shutdown::Both);
                return Err(SocksError::CommonError(constant::ADDRESS_TYPE_NOT_SUPPORT_ERR,
                                                   "ip address not supported ".to_string()));
            }
        }

        let host = stream.local_addr().unwrap();
        let mut rsp: Vec<u8> =
            vec![constant::SOCKS5, 0x00, 0x00, constant::IPV4, 127, 0x00, 0x00, 0x01, 0x00, 0x00];

        stream.write(rsp.as_slice());
        let _portindex = domain.len() - 2;
        let port = convert_port(domain.drain(_portindex..).take(2).collect());
        let mut _host: Vec<u8> = domain.drain(start..).collect();
        // clone new value,fuck rust move
        let _host_clone: Vec<u8> = _host.clone();
        let _domain = String::from_utf8(_host);
        if let Ok(address) = _domain {
            let host = format!("{}:{}", address, port as usize);
            println!("handle domain is {}", host);
            let mut s = try!(TcpStream::connect(&*host));
            Ok(s)
        } else {
            if _host_clone.len() == 4 {
                let ip = Ipv4Addr::new(_host_clone[0],
                                       _host_clone[1],
                                       _host_clone[2],
                                       _host_clone[3]);
                let mut s = try!(TcpStream::connect((ip, port)));
                Ok(s)
            } else {
                Err(SocksError::CommonError(constant::CMD_NOT_SUPPORT_ERR,
                                            "Command not supported".to_string()))
            }
        }
    }

    fn handle_udp(domain: &mut Vec<u8>) -> Result<(), SocksError> {
        Ok(())
    }
}

pub trait Listener {
    fn add_hook<F>(&self, hook: F) where F: Fn(&mut TcpStream) -> Result<(), SocksError>;
    fn bind(&self);
}

impl Listener for Server {
    fn add_hook<F>(&self, hook: F)
        where F: Fn(&mut TcpStream) -> Result<(), SocksError>
    {
        // TODO
    }
    fn bind(&self) {
        let host = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&*host).unwrap();
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    mioco::spawn(move || {
                        let handshake = Server::handshake(&mut stream).unwrap();
                        stream.write(&[constant::SOCKS5, handshake]);
                        if handshake == constant::AUTHENTICATION {
                            Server::authorization(&mut stream).unwrap();
                        }
                        Server::handle_request(&mut stream).unwrap();
                    });
                }
                Err(e) => {
                    println!("handle error {}", e);
                }
            }
        }
    }
}
