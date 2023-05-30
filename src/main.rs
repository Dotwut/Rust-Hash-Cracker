
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use sha2::{Sha256, Digest};
use std::process::exit;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Invalid number of arguments");
        println!("Example: cargo run <sha256 hash> <password file>");
        exit(1);
    }

    let wanted_hash: &String = &args[1];
    let password_file: &str = &args[2];
    let mut attempts: i32 = 1;

    println!("Attempting to crack: {}!\n", wanted_hash);

    let password_list: File = File::open(password_file).unwrap();
    let reader: BufReader<File> = BufReader::new(password_list);

    for line in reader.lines() {
        let line: String = line.unwrap();
        let password: Vec<u8> = line.trim().to_owned().into_bytes();
        let password_hash = format!("{:x}", Sha256::digest(&password));

        println!("[{}] {} == {}", attempts, std::str::from_utf8(&password).unwrap(), password_hash);
        if &password_hash == wanted_hash {
            println!("Password hash found after {} attempts! {} hashes to {}!",attempts, std::str::from_utf8(&password).unwrap(), password_hash);
            println!(r" ___      _               _     ___         _    ___      _   ");
            println!(r"|   \ ___| |___ __ ___  _| |_  | _ \_  _ __| |_ / __|__ _| |_ ");
            println!(r"| |) / _ \  _\ V  V / || |  _| |   / || (_-<  _| (__/ _` |  _|");
            println!(r"|___/\___/\__|\_/\_/ \_,_|\__| |_|_\\_,_/__/\__|\___\__,_|\__|");
            exit(0);
        }
        attempts +=1;
    }

    println!("Password hash not found!");
    println!(r" ___      _               _     ___         _    ___      _   ");
    println!(r"|   \ ___| |___ __ ___  _| |_  | _ \_  _ __| |_ / __|__ _| |_ ");
    println!(r"| |) / _ \  _\ V  V / || |  _| |   / || (_-<  _| (__/ _` |  _|");
    println!(r"|___/\___/\__|\_/\_/ \_,_|\__| |_|_\\_,_/__/\__|\___\__,_|\__|");

}
