use std::net::{TcpStream, Shutdown, SocketAddr, Ipv4Addr, Ipv6Addr};
use super::common::{SocksError, is_match};
use std::default::Default;
use super::constant;
use std::io::prelude::*;
use mioco;
use std::io;
use std::str::FromStr;
#[derive(Default)]
pub struct Client<'a> {
    host: &'a str,
    port: u16,
    username: &'a str,
    password: &'a str,
}

pub trait Request {
    fn handle_http(&self, stream: &mut TcpStream) -> Result<(), SocksError>;
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
    fn handle_http(&self, stream: &mut TcpStream) -> Result<(), SocksError> {
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
        // read 1024 byte and parser header
        let mut header: [u8; 1024] = [0; 1024];
        let real_size = try!(stream.read(&mut header));
        // to string
        let headers = String::from_utf8(header[..real_size].to_vec()).unwrap();
        let mut port: u16 = 80;
        let mut host: String;
        let mut https: bool = false;
        let mut url = match headers.split_whitespace().nth(1) {
            Some(_url) => _url,
            None => return Err(SocksError::CommonError(0x01, "invalid url".to_string())),
        };
        // parser ur1
        if url.contains("https") {
            port = 443;
            https = true;
        }

        if !url.contains("http") {
            https = true;
        }

        // what's the fuck api
        let mut v: Vec<&str> = url.split("//").collect();
        let mut host_index = 0;
        if v.len() >= 2 {
            host_index = 1;
        }
        if v[host_index].contains(":") {
            let host_port: Vec<&str> = v[host_index].split(":").collect();
            host = host_port[0].to_string();
            let _port = host_port[1].replace("/", "");
            port = u16::from_str(&_port).unwrap();
        } else {
            // some host contains url
            // //???????
            let mut _h: Vec<&str> = v[host_index].split("/").collect();
            host = _h[0].to_string();
        }
        if is_match(&host) {
            request.append(&mut vec![constant::IPV4]);
            let v: Vec<&str> = host.split(".").collect();
            request.append(&mut vec![v[0].as_ptr() as u8,
                                     v[1].as_ptr() as u8,
                                     v[2].as_ptr() as u8,
                                     v[3].as_ptr() as u8]);
            request.append(&mut vec![port as u8, (port >> 8) as u8]);
        } else {
            request.append(&mut vec![constant::DOMAIN]);
            request.append(&mut vec![host.as_bytes().len() as u8]);
            request.append(&mut host.as_bytes().to_vec());
            request.append(&mut vec![(port >> 8) as u8, port as u8]);
        }
        // write rsp
        //
        try!(_stream.write(&mut request));
        let mut rsp: [u8; 1024] = [0; 1024];
        try!(_stream.read(&mut rsp));
        if rsp[0] != constant::SOCKS5 || rsp[1] != 0x00u8 {
            _stream.shutdown(Shutdown::Both);
            return Err(SocksError::CommonError(0x01, "connect unreachable".to_string()));
        }
        if https {
            stream.write("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes());
        }

        // current test just for ipv4 and domain
        let mut client_write = _stream.try_clone().unwrap();
        let mut server_read = stream.try_clone().unwrap();
        let rh = mioco::spawn(move || {
            if !https {
                client_write.write(&mut header);
            }
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
