use std::net::{TcpStream, Shutdown, Ipv4Addr};
use super::super::common::{SocksError, convert_port, ConnWrap};
use super::super::constant;
use std::io::prelude::*;
use mioco;
pub trait TcpHandler {
    fn handle_request(&mut self) -> Result<(), SocksError>;
}
pub struct TcpstreamWrap<'a> {
    tcpstream: &'a mut TcpStream,
    buffer: &'a mut Vec<u8>,
}
impl<'a> TcpstreamWrap<'a> {
    pub fn new(tcpstream: &'a mut TcpStream, buf: &'a mut Vec<u8>) -> TcpstreamWrap<'a> {
        TcpstreamWrap {
            tcpstream: tcpstream,
            buffer: buf,
        }
    }
    fn handle_connect(domain: &mut Vec<u8>,
                      stream: &mut TcpStream)
                      -> Result<TcpStream, SocksError> {
        let ip_type = domain[0];
        // default is ipv4
        let mut ip_len = constant::IPV4_LEN;
        // default is ipv4
        let mut ip_len = constant::IPV4_LEN;
        let mut start = 1;
        match ip_type {
            constant::IPV4 => ip_len = constant::IPV4_LEN + 2,
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
                                   0x7f,
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
            vec![constant::SOCKS5, 0x00, 0x00, constant::IPV4, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00];

        stream.write(rsp.as_slice());
        let _portindex = domain.len() - 2;
        let port = convert_port(domain.drain(_portindex..).take(2).collect());
        let mut _host: Vec<u8> = domain.drain(start..).collect();
        let _host_clone: Vec<u8> = _host.clone();
        if ip_type == constant::DOMAIN {
            let address = String::from_utf8(_host).unwrap();
            let host = format!("{}:{}", address, port as usize);
            let mut s = try!(TcpStream::connect(&*host));
            Ok(s)
        } else {
            if _host_clone.len() == 4 {
                let ip = Ipv4Addr::new(_host_clone[0],
                                       _host_clone[1],
                                       _host_clone[2],
                                       _host_clone[3]);
                let mut s = try!(TcpStream::connect((ip, port)));
                return Ok(s);
            }
            Err(SocksError::CommonError(0x001, "does not support ipv6".to_string()))
        }
    }
}

impl<'a> TcpHandler for TcpstreamWrap<'a> {
    fn handle_request(&mut self) -> Result<(), SocksError> {
        let mut _stream_clone = self.tcpstream.try_clone().unwrap();

        let s = TcpstreamWrap::handle_connect(&mut self.buffer, &mut _stream_clone).unwrap();

        let mut client_reader = self.tcpstream.try_clone().unwrap();
        // clone s stream
        let mut server_writer = s.try_clone().unwrap();
        // move
        let rh = mioco::spawn(move || {
            ConnWrap::new(&mut client_reader, &mut server_writer).copy();
            client_reader.shutdown(Shutdown::Read);
            server_writer.shutdown(Shutdown::Write);
        });

        let mut client_writer = self.tcpstream.try_clone().unwrap();
        // clone s stream
        let mut server_reader = s.try_clone().unwrap();
        let wh = mioco::spawn(move || {
            ConnWrap::new(&mut server_reader, &mut client_writer).copy();
            server_reader.shutdown(Shutdown::Read);
            client_writer.shutdown(Shutdown::Write);
        });
        rh.join().unwrap();
        wh.join().unwrap();
        Ok(())
    }
}
