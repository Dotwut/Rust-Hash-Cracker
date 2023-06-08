use std::env;
use std::io::{Error, ErrorKind};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufRead, BufReader};
use ntlm_hash::ntlm_hash;
use md4::Md4;
use md5;
use sha1::{Sha1};
use sha2::{Sha256};
use sha2::{Sha512};
use sha3::{Sha3_256, Digest as Sha3_256Digest};
use std::process::exit;

fn print_help_message() {
    println!("\n{}\n",
    "Usage: cargo run <hash type> <hash> <password file>

Options:
    <hash type>         The type of the hash. This must be one of the following: 
                        NTLMv1, MD4, MD5, Sha1, Sha2_256, Sha2_512, Sha3_256
    <hash>              The hash to crack.
    <password file>     The path to the file containing the list of passwords to try.

Example:
    cargo run Sha256 abcdef1234567890 /home/dotwut/password.txt".yellow());
}

fn banner() {
    println!("{}", r" ___         _    ___      _   ".bold().purple());
    println!("{}", r"| _ \_  _ __| |_ / __|__ _| |_ ".bold().purple());
    println!("{}", r"|   / || (_-<  _| (__/ _` |  _|".bold().purple());
    println!("{}", r"|_|_\\_,_/__/\__|\___\__,_|\__|".bold().purple());
    println!("{}", " By: Dotwut".bold().purple());
    println!("{} {}", " Written in:".bold().purple(), "Rust".bold().truecolor(183, 65, 14));
}

fn compute_ntlmv1(input: &str) -> String {
    ntlm_hash(input)
}

fn compute_md4(input: &[u8]) -> String {
    let mut hasher = Md4::new();
    hasher.update(input);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn compute_md5(input: &[u8]) -> String {
    let result = md5::compute(input);
    format!("{:x}", result)
}

fn compute_sha1(input: &[u8]) -> String {
    let result = Sha1::digest(input);
    format!("{:x}", result)
}

fn compute_sha2_256(input: &[u8]) -> String {
    let result = Sha256::digest(input);
    format!("{:x}", result)
}

fn compute_sha2_512(input: &[u8]) -> String {
    let result = Sha512::digest(input);
    format!("{:x}", result)
}

fn compute_sha3_256(input: &[u8]) -> String {
    let result = Sha3_256::digest(input);
    format!("{:x}", result)
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        println!("{}", "Invalid number of arguments".red());
        print_help_message();
        return Err(Error::new(ErrorKind::InvalidInput, "Invalid number of arguments provided"));
    }

    let hash_type: &str = &args[1];
    let wanted_hash: &String = &args[2];
    let password_file: &str = &args[3];
    let mut attempts: i32 = 1;

    println!("Attempting to crack: {}!\n", wanted_hash);

    let password_list: File = match File::open(password_file) {
        Ok(file) => file,
        Err(err) => return Err(Error::new(ErrorKind::NotFound, format!("Failed to open password file: {}", err))),
    };
    let reader: BufReader<File> = BufReader::new(password_list);

    // Get total number of lines in the file for the progress bar
    let total_lines = reader.lines().count();
    let bar = ProgressBar::new(total_lines as u64);
    bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .progress_chars("##-"));

        for line in BufReader::new(File::open(password_file).unwrap()).lines() {
        let line: String = line.unwrap();
        let password: String = line.trim().to_owned();
        let password_hash: String = match hash_type {
            "NTLMv1" => compute_ntlmv1(&password),
            "MD4" => compute_md4(password.as_bytes()),
            "MD5" => compute_md5(password.as_bytes()),
            "Sha1" => compute_sha1(password.as_bytes()),
            "Sha2_256" => compute_sha2_256(password.as_bytes()),
            "Sha2_512" => compute_sha2_512(password.as_bytes()),
            "Sha3_256" => compute_sha3_256(password.as_bytes()),
            _ => panic!("WrongHash"),
        };
    
        println!("[{}] {} == {}", attempts, &password.red(), password_hash.red());
        bar.inc(1);  // Increment the bar
        if &password_hash == wanted_hash {
            bar.finish_with_message("Done");
            println!("Password hash found after {} attempts! {} hashes to {}!", attempts, &password.bold().green(), password_hash.bold().green());
            banner();
            exit(0);
        }
        attempts += 1;
    }

    println!("Password hash not found!");
    banner();
    Ok(())
}


