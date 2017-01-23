extern crate crypto;

use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;

use std::mem;

fn hmac_sha1(key : &[u8], message: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha1::new(), key);

    for i in message.iter() {
        hmac.input(&[*i])
    }

    let result = hmac.result();
    result.code().to_vec()
}

fn offset(b : &[u8]) -> usize {
    (b.last().unwrap() & 0xf) as usize
}

fn sbits(bits: &[u8]) -> u32 {
    let offset = offset(bits);
    unsafe { mem::transmute::<[u8; 4], u32>(
            [
            bits[offset+3],
            bits[offset+2],
            bits[offset+1],
            bits[offset] & 0x7f
            ]
            )
    }
}

pub fn hotp(digits : u32, k : &[u8], c : &[u8]) -> u32 {
    let hmac_value = hmac_sha1(k, c);
    let dbc = sbits(hmac_value.as_slice());
    dbc % 10u32.pow(digits)
}

fn to_bytes(x : u64) -> [u8; 8] {
    let mut temp = [0u8; 8];
    for byte_index in 0..8 {
        let shift_amount: usize = 8 * (7 - byte_index);
        temp[byte_index] = (x >> shift_amount) as u8;
    }
    temp
}

pub fn totp(digits : u32, k : &[u8], time : u64) -> u32 {
    let t0 = 0;
    let timestep = 30;

    let t = (time - t0) / timestep;

    hotp(digits, k, &to_bytes(t))
}
