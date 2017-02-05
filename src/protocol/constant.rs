pub const METHODS: u8 = 258;
pub const NMETHODS: u8 =1;
pub const VER: u8 = 0;

//for request
pub  const CMD: u8 = 1;
pub  const RSV: u8 = 1;
pub  const ATYP: u8 = 1;

//ip type
pub  const IPV4: u8= 0x01;
pub  const IPV6: u8= 0x03;
pub  const DOMAIN: u8= 0x04;

//cmd type
pub  const CONNECT: u8= 0x01;
pub  const BIND: u8= 0x02;
pub  const UDP: u8= 0x03;

//method type
pub  const NO_AUTHENTICATION: u8= 0x00;
pub  const GSSAPI: u8= 0x01;
pub  const AUTHENTICATION: u8= 0x02;
pub  const IANA: u8= 0x03;
pub  const RESERVED: u8= 0x80;
pub  const NO_ACCEPTABLE: u8= 0xff;


//ip length
pub  const IPV4_LEN: u8= 4u8;
pub  const IPV6_LEN: u8= 16u8;

//version
pub const SOCKS5: u8 = 0x05;