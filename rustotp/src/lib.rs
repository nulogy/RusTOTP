extern crate rusthotp;

use rusthotp::{ HotpOutput, hotp };

fn to_bytes(x: i64) -> [u8; 8] {
    let mut temp = [0u8; 8];
    for byte_index in 0..8 {
        let shift_amount: usize = 8 * (7 - byte_index);
        temp[byte_index] = (x >> shift_amount) as u8;
    }
    temp
}

pub fn totp(desired_code_length: usize, timestep: i64, key: &[u8], time: i64) -> HotpOutput {
    let t = time / timestep;
    hotp(desired_code_length, key, &to_bytes(t))
}
