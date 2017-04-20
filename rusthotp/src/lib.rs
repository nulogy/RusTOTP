extern crate crypto;

use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;

use std::fmt;

/// This implementation of HMAC-Based One Time Passwords proceeds in three
/// stages, as per [RFC 4226](https://www.ietf.org/rfc/rfc4226.txt):
///
/// 1. Generate an HMAC-SHA-1 value given a shared secret `key` and a
/// moving factor `counter` that *should* change on every use
/// 2. Extraction of a 4-byte value from the SHA-1 digest
/// 3. Deriving a final HOTP value between 0 and
/// 10^{`desired_code_length`}-1 from the 4-byte value extracted
/// in the last step.
///
/// Note that it is the responsibility of the caller to:
///
/// * Fulfill the precondition that `counter` is an 8-byte value
/// * Increment the counter accordingly per invocation
///
/// # Examples
///
/// To generate an HOTP value between 0 and 10^8 - 1, given the shared
/// secret ASCII key `"Hello world!"` and current counter `0`:
///
/// ```
/// rusthotp::hotp(8, "Hello world!".as_bytes(), [0; 8]);
/// ```
pub fn hotp(desired_code_length: usize, key: &[u8], counter: &[u8]) -> HotpOutput {
    let hmac_value = hmac_sha1(key, counter);
    let dbc = sbits(hmac_value.as_slice());
    HotpOutput{ code: dbc % 10u32.pow(desired_code_length as u32), length: desired_code_length }
}

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
