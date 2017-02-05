extern crate socks5;
use socks5::protocol::server::{Server,Listener};

fn main(){
    let s = Server::new("127.0.0.1".to_string(),1080u16);
    s.bind();
}