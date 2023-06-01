use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use sha2::{Sha256, Digest};
use md5;
use std::process::exit;

fn banner() {
    println!(r" ___         _    ___      _   ");
    println!(r"| _ \_  _ __| |_ / __|__ _| |_ ");
    println!(r"|   / || (_-<  _| (__/ _` |  _|");
    println!(r"|_|_\\_,_/__/\__|\___\__,_|\__|");
    println!(" By: Dotwut");
    println!(" Written in: Rust");
}

fn compute_md5(input: &[u8]) -> String {
    let result = md5::compute(input);
    format!("{:x}", result)
}

fn compute_sha256(input: &[u8]) -> String {
    let result = Sha256::digest(input);
    format!("{:x}", result)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        println!("Invalid number of arguments");
        println!("Example: cargo run <hash type> <hash> <password file>");
        println!("Hash Types: Sha256, MD5");
        exit(1);
    }

    let hash_type: &str = &args[1];
    let wanted_hash: &String = &args[2];
    let password_file: &str = &args[3];
    let mut attempts: i32 = 1;

    println!("Attempting to crack: {}!\n", wanted_hash);

    let password_list: File = File::open(password_file).unwrap();
    let reader: BufReader<File> = BufReader::new(password_list);

    for line in reader.lines() {
        let line: String = line.unwrap();
        let password: Vec<u8> = line.trim().to_owned().into_bytes();
        let password_hash: String = match hash_type {
            "Sha256" => compute_sha256(&password),
            "MD5" => compute_md5(&password),
            _ => panic!("WrongHash"),
        };

        println!("[{}] {} == {}", attempts, std::str::from_utf8(&password).unwrap(), password_hash);
        if &password_hash == wanted_hash {
            println!("Password hash found after {} attempts! {} hashes to {}!",attempts, std::str::from_utf8(&password).unwrap(), password_hash);
            banner();
            exit(0);
        }
        attempts +=1;
    }

    println!("Password hash not found!");
    banner();

}


