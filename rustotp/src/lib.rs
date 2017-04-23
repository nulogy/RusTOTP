extern crate rusthotp;

use rusthotp::{ HotpOutput, hotp };

/// Implements the Time-Based One-Time Password algorithm described in [RFC
/// 6238](https://tools.ietf.org/html/rfc6238),
///
/// This function will produce a different one-time password with
/// `desired_code_length` digits every `timestep` seconds relative
/// to the Unix epoch, given the current time `time`.
///
/// # Examples
///
/// To generate a 6-digit TOTP value given the ASCII shared secret `"Hello world!"`
/// that will rotate every 5 seconds, given that the current time is the Unix epoch:
///
/// ```
/// let six_digit_result = rustotp::totp(6, 5, "Hello world!".as_bytes(), 0);
/// assert_eq!(format!("{}", six_digit_result), "124111");
/// ```
///
/// To generate an 8-digit TOTP value given the ASCII shared secret `"12345678901234567890"`
/// that will rotate every 30 seconds, assuming it is currently 59 seconds after the Unix epoch:
///
/// ```
/// let eight_digit_result = rustotp::totp(8, 30, "12345678901234567890".as_bytes(), 59);
/// assert_eq!(format!("{}", eight_digit_result), "94287082");
/// ```
pub fn totp(desired_code_length: usize, timestep: i64, key: &[u8], time: i64) -> HotpOutput {
    let t = time / timestep;
    hotp(desired_code_length, key, &to_bytes(t))
}

fn to_bytes(x: i64) -> [u8; 8] {
    let mut temp = [0u8; 8];
    for byte_index in 0..8 {
        let shift_amount: usize = 8 * (7 - byte_index);
        temp[byte_index] = (x >> shift_amount) as u8;
    }
    temp
}
