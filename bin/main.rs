extern crate rfc6238;
extern crate chrono;

pub fn main() {
 let key = "12345678901234567890".as_bytes();
    let current_time = 59;
    let totp_value = rfc6238::totp(8, key, current_time);
    println!("{}", totp_value);
}
