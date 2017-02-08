extern crate socks5;
use socks5::protocol::client::{Client, Request};
use std::net::TcpListener;
use std::thread;
fn main() {
    let listener = TcpListener::bind("127.0.0.1:5555").unwrap();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                thread::spawn(move || {
                    let client = Client::new("127.0.0.1", 1080u16);
                    let result = client.exchange(&mut stream);
                    match result {
                        Ok(_) => {
                            println!("handle ok msg");
                        }
                        Err(e) => {
                            println!("handle error msg {:?}", e);
                        }
                    }
                });
            }
            Err(e) => println!("handle error msg {:?}", e),
        }
    }
}