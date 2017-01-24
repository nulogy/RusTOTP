extern crate rfc6238;

extern crate chrono;
use chrono::*;

extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

extern crate base32;

use std::{process, thread, time, io};
use std::io::prelude::*;
use std::str::FromStr;

const VERSION: &'static str = "0.1";
const USAGE: &'static str = "
totp-client

Usage:
  totp-client <key> [--code-length=<cl>] [--time=<timestamp>] [--timestep=<ts>] [--interactive]
  totp-client --version
  totp-client (-h | --help)

Options:
  -h --help             Show this screen.
  --version             Show version.
  --code-length=<l>     Specifies the desired length of the output code, defaults to 6
  --time=<timestamp>    Specifies the unix timestamp to be used, defaults to current time
  --timestep=<ts>       Specifies the amount of time in seconds to wait until generating a new TOTP value, defaults to 30
  --interactive         Regenerate TOTP codes after timestep expiry, until program is terminated
";

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_key: String,
    flag_version: bool,
    flag_help: bool,
    flag_code_length: Option<String>,
    flag_time: Option<u64>,
    flag_timestep: Option<u64>,
    flag_interactive: bool,
}

fn interactive(key: &[u8], code_length: u8, timestep: u64) {
    let mut stderr = io::stderr();
    let mut current_time = UTC::now().timestamp();

    println!("{}", rfc6238::format_code(rfc6238::totp(code_length, timestep, key, current_time as u64), code_length as usize));

    let mut full_line = String::with_capacity(timestep as usize);
    for _ in 0..timestep {
        full_line.push('#');
    }
    writeln!(stderr, "{}", full_line).unwrap();

    let mut seconds = current_time % timestep as i64;

    let mut partial_line = String::with_capacity(timestep as usize);
    for _ in 0..seconds {
        partial_line.push('#');
    }
    stderr.write(partial_line.as_bytes()).unwrap();

    loop {
        if seconds == 0 as i64 {
            println!("\n{}", rfc6238::format_code(rfc6238::totp(code_length, timestep, key, current_time as u64), code_length as usize));
            writeln!(stderr, "{}", full_line).unwrap();
        }
        thread::sleep(time::Duration::from_secs(1));
        current_time = UTC::now().timestamp();
        seconds = current_time % timestep as i64;
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

    let alphabet = base32::Alphabet::RFC4648 { padding: true };
    let decoded_key = base32::decode(alphabet, args.arg_key.to_uppercase().as_str()).unwrap_or_else(|| {
        writeln!(io::stderr(), "Failed to base32-decode key, quitting").unwrap();
        process::exit(1);
    });
    let raw_code_length = args.flag_code_length.unwrap_or(String::from_str("6").unwrap());
    let code_length: u8 = raw_code_length.parse().unwrap();
    let timestamp = args.flag_time.unwrap_or(UTC::now().timestamp() as u64);
    let timestep = args.flag_timestep.unwrap_or(30);

    if args.flag_interactive {
        interactive(decoded_key.as_slice(), code_length, timestep);
        process::exit(0);
    }

    let code = rfc6238::totp(code_length, timestep, args.arg_key.as_bytes(), timestamp);
    println!("{}", rfc6238::format_code(code, code_length as usize));
}
