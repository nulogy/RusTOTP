extern crate rfc6238;

extern crate chrono;
use chrono::*;

extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

use std::process;
use std::str::FromStr;

const VERSION: &'static str = "0.1";
const USAGE: &'static str = "
totp-client

Usage:
  totp-client <key> [--code-length=<cl>] [--time=<timestamp>]
  totp-client --version
  totp-client (-h | --help)

Options:
  -h --help             Show this screen.
  --version             Show version.
  --code-length=<l>     Specifies the desired length of the output code, defaults to 6
  --time=<timestamp>    Specifies the unix timestamp to be used, defaults to current time
";

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_key: String,
    flag_version: bool,
    flag_help: bool,
    flag_code_length: Option<String>,
    flag_time: Option<u64>
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

    let raw_code_length = args.flag_code_length.unwrap_or(String::from_str("6").unwrap());
    let code_length: u8 = raw_code_length.parse().unwrap();
    let timestamp = args.flag_time.unwrap_or(UTC::now().timestamp() as u64);

    println!("{}", args.arg_key);
    println!("{}", code_length);
    println!("{}", timestamp);
}
