use super::super::common::{ConnWrap, SocksError, convert_port};
use super::super::constant;
use std::io::{Read, Write, ErrorKind};
use std::net::{TcpStream, Shutdown, SocketAddr, SocketAddrV4};
use std::io;
use mioco;
use mioco::udp::UdpSocket;
use mioco::mio::Ipv4Addr;
use std::thread;
use std::time;

pub struct UDPServer<'a> {
    host: &'a str,
    port: u16,
    stream: &'a mut TcpStream,
}
pub trait UDPHandler {
    fn handle_request(&mut self) -> Result<(), SocksError>;
}

pub struct UDPWrap {
    udpsocket: UdpSocket,
    src: SocketAddr,
}

impl UDPWrap {
    fn new(src: SocketAddr, udpsocket: UdpSocket) -> UDPWrap {
        UDPWrap {
            src: src,
            udpsocket: udpsocket,
        }
    }
}
impl Read for UDPWrap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut copy = buf;
        let (size, _) = try!(self.udpsocket.recv(&mut copy));
        Ok(size)
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut size: usize = 0;
        let mut buffer: [u8; 8 * 1024] = [0; 8 * 1024];
        loop {
            let len = match self.udpsocket.recv(&mut buffer) {
                Ok((0, _)) => return Ok(size),
                Ok((len, _)) => len,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            buf.append(&mut buffer.to_vec());
            size += len;
        }
        Ok(size)
    }
}

impl Write for UDPWrap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.udpsocket.send(buf, &self.src)
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(ErrorKind::Other, "not implement"))
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut start = 0;
        loop {
            let wsize = try!(self.udpsocket.send(&buf[start..], &self.src));
            if start + wsize < buf.len() {
                start += wsize;
                continue;
            }
            break;
        }
        Ok(())
    }
}
impl<'a> UDPServer<'a> {
    pub fn new(host: &'a str, port: u16, stream: &'a mut TcpStream) -> UDPServer<'a> {
        UDPServer {
            host: host,
            port: port,
            stream: stream,
        }
    }
}

impl<'a> UDPHandler for UDPServer<'a> {
    fn handle_request(&mut self) -> Result<(), SocksError> {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, self.port));
        let mut socket = UdpSocket::v4().unwrap();
        socket.bind(&addr).unwrap();
        self.stream.write(&[constant::SOCKS5,
                            0x00,
                            0x00,
                            constant::IPV4,
                            0x7f,
                            0x00,
                            0x00,
                            0x01,
                            (self.port >> 8) as u8,
                            self.port as u8]);
        let mut buffer: [u8; 1024] = [0; 1024];
        let (size, src) = try!(socket.recv(&mut buffer));
        // println!("src is {:?},buffer is {:?}", src, buffer.to_vec());
        if buffer[0] != 0x00u8 || buffer[1] != 0x00u8 {
            // rsv invalid
            return Err(SocksError::CommonError(0x001, "fragment  is not implement".to_string()));
        }
        let mut ip_len: usize = constant::IPV4_LEN;
        let mut start = 4;
        match buffer[3] {
            constant::IPV4 => ip_len = constant::IPV4_LEN,
            // the last is port size
            constant::DOMAIN => {
                let mut ipbuf: [u8; 1] = [buffer[4]];
                start = 5;
                // try!(socket.recv(&mut ipbuf));
                ip_len = ipbuf[0] as usize;
            }
            constant::IPV6 => ip_len = constant::IPV6_LEN,
            _ => ip_len = 0,
        };
        let mut host_buf: Vec<u8> = buffer[5..ip_len + 7].to_vec();
        // try!(socket.recv(&mut host_buf));
        let port = convert_port(host_buf[ip_len..].to_vec());
        let mut tcpstream: TcpStream;
        match buffer[3] {
            constant::DOMAIN => {
                let host = String::from_utf8(host_buf[0..ip_len].to_vec()).unwrap();
                let raddress = format!("{}:{}", host, port);
                tcpstream = try!(TcpStream::connect(&*raddress));
            }
            constant::IPV4 => {
                let ip = Ipv4Addr::new(host_buf[0], host_buf[1], host_buf[2], host_buf[3]);
                tcpstream = try!(TcpStream::connect((ip, port)));
            }
            constant::IPV6 => {
                return Err(SocksError::CommonError(0x001, "not implement".to_string()));
            }
            _ => return Err(SocksError::CommonError(0x001, "not implement".to_string())),
        }
        // write resut to client
        // +----+------+------+----------+----------+----------+
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        // +----+------+------+----------+----------+----------+
        // | 2  |  1   |  1   | Variable |    2     | Variable |
        // +----+------+------+----------+----------+----------+
        // copy data from udp
        // given udp rsp
        socket.send(&[0x00,
                      0x00,
                      0x00,
                      0x01,
                      0x7f,
                      0x00,
                      0x00,
                      0x01,
                      (self.port >> 8) as u8,
                      self.port as u8],
                    &src);
        try!(tcpstream.write(&buffer[ip_len + 2..size]));
        let mut tcp_writer = tcpstream.try_clone().unwrap();
        let mut udp_reader = socket.try_clone().unwrap();
        if size >= 1024 {
            mioco::spawn(move || {
                match ConnWrap::new(&mut UDPWrap::new(src, udp_reader), &mut tcp_writer).copy() {
                    Err(e) => {
                        println!("handle read error {}", e);
                    }
                    Ok(_) => {
                        println!("read ok......");
                    }
                }
                tcp_writer.shutdown(Shutdown::Write);
            });
        }
        let mut tcp_reader = tcpstream.try_clone().unwrap();
        let mut udp_writer = socket.try_clone().unwrap();
        let wh = mioco::spawn(move || {
            match ConnWrap::new(&mut tcp_reader, &mut UDPWrap::new(src, udp_writer)).copy() {
                Err(e) => {
                    println!("handle write error {}", e);
                }
                Ok(_) => {
                    println!("write ok......");
                }
            }
            tcp_reader.shutdown(Shutdown::Read);
        });
        wh.join().unwrap();
        self.stream.shutdown(Shutdown::Both);
        drop(socket);
        println!("exit data copy....");
        Ok(())
    }
}