pub const VER: usize = 1;

// for request
pub const CMD: usize = 1;
pub const RSV: usize = 1;
pub const ATYP: usize = 1;

// ip type
pub const IPV4: u8 = 0x01;
pub const IPV6: u8 = 0x04;
pub const DOMAIN: u8 = 0x03;

// cmd type
pub const CONNECT: u8 = 0x01;
pub const BIND: u8 = 0x02;
pub const UDP: u8 = 0x03;

// method type
pub const GSSAPI: u8 = 0x01;
pub const AUTHENTICATION: u8 = 0x02;
pub const IANA: u8 = 0x03;
pub const RESERVED: u8 = 0x80;
pub const NO_ACCEPTABLE: u8 = 0xff;


// ip length
pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

// version
pub const SOCKS5: u8 = 0x05;

// error
pub const COMMON_ERR: usize = 0x01;
pub const CONNECT_ERR: usize = 0x02;
pub const NETWORK_UNREACHABLE_ERR: usize = 0x03;
pub const HOST_UNREACHABLE_ERR: usize = 0x04;
pub const CONNECT_REFUSED_ERR: usize = 0x05;
pub const TTL_EXPIRED_ERR: usize = 0x06;
pub const CMD_NOT_SUPPORT_ERR: usize = 0x07;
pub const ADDRESS_TYPE_NOT_SUPPORT_ERR: usize = 0x08;

pub const DEFAULT_SIZE: usize = 1024;

// ipv4 pattern
pub const IPV4_PATTERN: &'static str = "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.\
                                        ){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";