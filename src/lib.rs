extern crate crypto;

use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;

use std::fmt;

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha1::new(), key);

    for i in message.iter() {
        hmac.input(&[*i])
    }

    let result = hmac.result();
    result.code().to_vec()
}

fn offset(b: &[u8]) -> usize {
    (b.last().unwrap() & 0xf) as usize
}

fn sbits(bits: &[u8]) -> u32 {
    let offset = offset(bits);

    let mut val: u32 = 0;
    val += bits[offset + 3] as u32;
    val += (bits[offset + 2] as u32) << 8;
    val += (bits[offset + 1] as u32) << 16;
    val += ((bits[offset] as u32) & 0x7f) << 24;
    val
}

pub struct HotpOutput {
    pub code: u32,
    pub length: usize,
}

impl fmt::Display for HotpOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:0length$}", self.code, length = self.length)
    }
}

pub fn hotp(desired_code_length: usize, key: &[u8], counter: &[u8]) -> HotpOutput {
    let hmac_value = hmac_sha1(key, counter);
    let dbc = sbits(hmac_value.as_slice());
    HotpOutput{ code: dbc % 10u32.pow(desired_code_length as u32), length: desired_code_length }
}

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
