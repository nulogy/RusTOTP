extern crate rfc6238;

extern crate chrono;
use chrono::*;

extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

extern crate base64;
use base64::decode;

use std::{process, thread, time, io};
use std::io::prelude::*;
use std::str::FromStr;

const VERSION: &'static str = "0.1";
const USAGE: &'static str = "
totp-client

Usage:
  totp-client <key> [--code-length=<cl>] [--time=<timestamp>] [--interactive]
  totp-client --version
  totp-client (-h | --help)

Options:
  -h --help             Show this screen.
  --version             Show version.
  --code-length=<l>     Specifies the desired length of the output code, defaults to 6
  --time=<timestamp>    Specifies the unix timestamp to be used, defaults to current time
  --interactive         Regenerate TOTP codes after timestep expiry, until program is terminated
";

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_key: String,
    flag_version: bool,
    flag_help: bool,
    flag_code_length: Option<String>,
    flag_time: Option<u64>,
    flag_interactive: bool,
}

const TIMESTEP: u32 = 30;

fn interactive(key: &[u8], code_length: u8) {
    let mut stderr = io::stderr();
    let mut current_time = UTC::now().timestamp();

    println!("{}", rfc6238::totp(code_length, key, current_time as u64));

    let mut full_line = String::with_capacity(TIMESTEP as usize);
    for _ in 0..TIMESTEP {
        full_line.push('#');
    }
    writeln!(stderr, "{}", full_line).unwrap();

    let mut partial_line = String::with_capacity(TIMESTEP as usize);
    let mut seconds = current_time % TIMESTEP as i64;
    for _ in 0..seconds {
        partial_line.push('#');
    }
    stderr.write(partial_line.as_bytes()).unwrap();

    loop {
        if seconds == 0 as i64 {
            println!("\n{}", rfc6238::totp(code_length, key, current_time as u64));
            writeln!(stderr, "{}", full_line).unwrap();
        }
        thread::sleep(time::Duration::from_secs(1));
        current_time = UTC::now().timestamp();
        seconds = current_time % TIMESTEP as i64;
        stderr.write("#".as_bytes()).unwrap();
    }
}

pub fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());
    if args.flag_version {
        println!("{}", VERSION);
        process::exit(0);
    }

    if args.flag_help {
        println!("{}", USAGE);
        process::exit(0);
    }

    let decoded_key = decode(args.arg_key.as_str()).unwrap();
    let raw_code_length = args.flag_code_length.unwrap_or(String::from_str("6").unwrap());
    let code_length: u8 = raw_code_length.parse().unwrap();
    let timestamp = args.flag_time.unwrap_or(UTC::now().timestamp() as u64);

    if args.flag_interactive {
        interactive(decoded_key.as_slice(), code_length);
        process::exit(0);
    }

    let code = rfc6238::totp(code_length, decoded_key.as_slice(), timestamp);
    println!("{}", code);
}
