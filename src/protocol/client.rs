use std::net::{TcpStream, Shutdown, SocketAddr, Ipv4Addr, Ipv6Addr};
use super::common::SocksError;
use std::default::Default;
use super::constant;
use std::io::prelude::*;
use mioco;
use std::io;
#[derive(Default)]
pub struct Client<'a> {
    host: &'a str,
    port: u16,
    username: &'a str,
    password: &'a str,
}

pub trait Request {
    fn exchange(&self, stream: &mut TcpStream) -> Result<(), SocksError>;
}

impl<'a> Client<'a> {
    pub fn new(host: &'a str, port: u16) -> Client {
        Client {
            host: host,
            port: port,
            username: "",
            password: "",
        }
    }
    pub fn new_with_auth(host: &'a str,
                         username: &'a str,
                         password: &'a str,
                         port: u16)
                         -> Client<'a> {
        Client {
            host: host,
            port: port,
            username: username,
            password: password,
        }
    }
}

impl<'a> Request for Client<'a> {
    fn exchange(&self, stream: &mut TcpStream) -> Result<(), SocksError> {
        let address = format!("{}:{}", self.host, self.port);
        let mut _stream = try!(TcpStream::connect(&*address));
        // define message size
        if self.username != "" && self.password != "" {
            try!(_stream.write(&[constant::SOCKS5, 0x02, 0x00, constant::AUTHENTICATION]));
        } else {
            try!(_stream.write(&[constant::SOCKS5, 0x02, 0x00]));
        }
        let mut rbuffer: [u8; 2] = [0; 2];
        let size = try!(_stream.read(&mut rbuffer));
        if size < 2 {
            _stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(0x01, "handshake failed".to_string()));
        }
        if rbuffer[1] == constant::AUTHENTICATION {
            let mut auth: Vec<u8> = vec![0x01];
            auth.append(&mut vec![self.username.len() as u8]);
            auth.append(&mut self.username.as_bytes().to_vec());
            auth.append(&mut vec![self.password.len() as u8]);
            auth.append(&mut self.password.as_bytes().to_vec());
            try!(_stream.write(&auth));
            let mut reply: [u8; 2] = [0; 2];
            let s = try!(_stream.read(&mut reply));
            if s < 2 {
                _stream.shutdown(Shutdown::Both);
                return Err(SocksError::CommonError(0x01, "authentication failed".to_string()));
            }
            if reply[1] != 0x00u8 {
                _stream.shutdown(Shutdown::Both);
                return Err(SocksError::CommonError(0x01, "authentication failed".to_string()));
            }
        }
        // current support connect method only
        let mut request: Vec<u8> = vec![0x05u8, constant::CONNECT, 0x00];

        // send request
        let remote_addr = stream.peer_addr().unwrap();
        match remote_addr {
            SocketAddr::V4(ipv4) => {
                request.append(&mut vec![constant::IPV4]);
                request.append(&mut ipv4.ip().octets().to_vec());
                let port: u16 = ipv4.port();
                // rsp.append(ipv4.port());
                request.append(&mut [port as u8, (port >> 8) as u8].to_vec());
            }
            SocketAddr::V6(ipv6) => {
                // TODO
                request.append(&mut vec![constant::IPV6]);
                request.append(&mut ipv6.ip().octets().to_vec());
                let port: u16 = ipv6.port();
                // rsp.append(ipv4.port());
                request.append(&mut [port as u8, (port >> 8) as u8].to_vec());
            }
        }
        println!("request buffer is {:?}", request);
        try!(_stream.write(&mut request));
        let mut rsp: [u8; 1024] = [0; 1024];
        try!(_stream.read(&mut rsp));
        if rsp[0] != constant::SOCKS5 || rsp[1] == 0x00u8 {
            _stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(0x01, "connect unreachable".to_string()));
        }
        let mut client_write = _stream.try_clone().unwrap();
        let mut server_read = stream.try_clone().unwrap();
        let rh = mioco::spawn(move || {
            io::copy(&mut server_read, &mut client_write);
            server_read.shutdown(Shutdown::Read);
            client_write.shutdown(Shutdown::Write);
        });
        let mut client_read = _stream.try_clone().unwrap();
        let mut server_write = stream.try_clone().unwrap();
        let wh = mioco::spawn(move || {
            io::copy(&mut client_read, &mut server_write);
            client_read.shutdown(Shutdown::Read);
            server_write.shutdown(Shutdown::Write);
        });
        rh.join().unwrap();
        wh.join().unwrap();
        Ok(())

    }
}
