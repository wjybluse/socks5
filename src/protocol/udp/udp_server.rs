use std::net::{UdpSocket, TcpStream, SocketAddrV6, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use super::super::common::{ConnWrap, SocksError, convert_port};
use super::super::constant;
use std::io::{Read, Write, ErrorKind};
use std::io;
use mioco;

pub struct UDPServer<'a> {
    host: &'a str,
    port: u16,
}
pub trait UDPHandler {
    fn handle_request(&self) -> Result<(), SocksError>;
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
        let (size, _) = try!(self.udpsocket.recv_from(&mut copy));
        Ok(size)
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut size: usize = 0;
        let mut buffer: [u8; 8 * 1024] = [0; 8 * 1024];
        loop {
            let len = match self.udpsocket.recv_from(&mut buffer) {
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
        self.udpsocket.send_to(buf, self.src)
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(ErrorKind::Other, "not implement"))
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut start = 0;
        loop {
            let wsize = try!(self.udpsocket.send_to(&buf[start..], self.src));
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
    pub fn new(host: &'a str, port: u16) -> UDPServer<'a> {
        UDPServer {
            host: host,
            port: port,
        }
    }
}

impl<'a> UDPHandler for UDPServer<'a> {
    fn handle_request(&self) -> Result<(), SocksError> {
        let address = format!("{}:{}", self.host, self.port);

        let socket = try!(UdpSocket::bind(&*address));
        let mut buffer: [u8; 4] = [0; 4];
        println!("recieve buffer is ");
        let (_, src) = try!(socket.recv_from(&mut buffer));
        if buffer[0] != 0x00u8 || buffer[1] != 0x00u8 {
            // rsv invalid
            return Err(SocksError::CommonError(0x001, "rsv is invalid".to_string()));
        }
        // flag size 0
        if buffer[2] != 0x00u8 {
            return Err(SocksError::CommonError(0x001, "fragment  is not implement".to_string()));
        }
        let mut ip_len: usize = constant::IPV4_LEN;
        match buffer[3] {
            constant::IPV4 => ip_len = constant::IPV4_LEN + 2,
            // the last is port size
            constant::DOMAIN => {
                let mut ipbuffer: [u8; 1] = [0; 1];
                try!(socket.recv_from(&mut ipbuffer));
                ip_len = ipbuffer[0] as usize;
            }
            constant::IPV6 => ip_len = constant::IPV6_LEN + 2,
            _ => ip_len = 0,
        };
        let mut address_buffer: Vec<u8> = Vec::with_capacity(ip_len);
        try!(socket.recv_from(&mut address_buffer));
        let port = convert_port(address_buffer[ip_len - 2..].to_vec());
        let mut tcpstream: TcpStream;
        match buffer[3] {
            constant::DOMAIN => {
                let host = String::from_utf8(address_buffer[0..ip_len - 2].to_vec()).unwrap();
                let raddress = format!("{}:{}", host, port);
                tcpstream = try!(TcpStream::connect(&*raddress));
            }
            constant::IPV4 => {
                let ip = Ipv4Addr::new(address_buffer[0],
                                       address_buffer[1],
                                       address_buffer[2],
                                       address_buffer[3]);
                tcpstream = try!(TcpStream::connect((ip, port)));
            }
            constant::IPV6 => {
                // let socket_address =
                //     SocketAddrV6::new(Ipv6Addr::from(*&address_buffer[0..16]), port, 0, 0);
                // tcpstream = try!(TcpStream::connect(socket_address));
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
        socket.send_to(&[0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x7f,
                         0x00,
                         0x00,
                         0x01,
                         self.port as u8,
                         (self.port >> 8) as u8],
                       src);
        let mut tcp_writer = tcpstream.try_clone().unwrap();
        let mut udp_reader = socket.try_clone().unwrap();
        let rh = mioco::spawn(move || {
            ConnWrap::new(&mut UDPWrap::new(src, udp_reader), &mut tcp_writer).copy().unwrap();
            tcp_writer.shutdown(Shutdown::Write);
        });
        let mut tcp_reader = tcpstream.try_clone().unwrap();
        let mut udp_writer = socket.try_clone().unwrap();
        let wh = mioco::spawn(move || {
            ConnWrap::new(&mut tcp_reader, &mut UDPWrap::new(src, udp_writer)).copy().unwrap();
            tcp_reader.shutdown(Shutdown::Read);
        });
        rh.join().unwrap();
        wh.join().unwrap();
        Ok(())
    }
}