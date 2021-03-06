extern crate hmacsha1;

use std::fmt;

/// This implementation of HMAC-Based One Time Passwords proceeds in three stages, as per [RFC
/// 4226](https://www.ietf.org/rfc/rfc4226.txt):
///
/// 1. Generate an HMAC-SHA-1 value given a shared secret `key` and a moving factor `counter` that *should* change on
///    every use
/// 2. Extraction of an indexing offset by reading the 4 low-order bits of the last byte of the SHA-1 digest
/// 3. Extraction of a 4-byte value from the SHA-1 digest, starting at the index offset determined by the previous step
/// 4. Deriving a final HOTP value between 0 and 10^{`desired_code_length`} -1 from the 4-byte value extracted in the
///    previous step.
///
/// Note that it is the responsibility of the caller to increment the counter accordingly per invocation. Consider the
/// use of the [byteorder crate](https://crates.io/crates/byteorder) if you need to convert from a numeric type into the
/// array of 8 bytes that are expected by `hotp()`.
///
/// # Examples
///
/// To generate a six-digit HOTP value (i.e. between 0 and 10^6 - 1), given the shared secret ASCII key `"Hello world!"`
/// and current counter `0`:
///
/// ```
/// let six_digit_result = rusthotp::hotp(6, "Hello world!".as_bytes(), &[0; 8]);
/// assert_eq!(format!("{}", six_digit_result), "124111");
/// ```
///
/// To generate an eight-digit HOTP value (i.e. between 0 and 10^8 - 1), given the shared secret ASCII key
/// `"12345678901234567890"` and current counter `1`:
///
/// ```
/// let eight_digit_result = rusthotp::hotp(8, "12345678901234567890".as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 1]);
/// assert_eq!(format!("{}", eight_digit_result), "94287082");
/// ```
///
/// To generate a six-digit HOTP value given the shared secret ASCII key "Hello world!" and the unix timestamp
/// 1493006116 as the counter:
///
/// ```
/// # extern crate byteorder;
/// # extern crate rusthotp;
/// # fn main() {
/// use byteorder::{BigEndian, ByteOrder};
/// let timestamp : i64 = 1493006116;
/// let mut unpacked_timestamp = [0; 8];
/// BigEndian::write_i64(&mut unpacked_timestamp, timestamp);
/// let result = rusthotp::hotp(6, "Hello world!".as_bytes(), &unpacked_timestamp);
///
/// assert_eq!(format!("{}", result), "106286");
/// # }
/// ```


pub fn hotp(desired_code_length: usize, key: &[u8], counter: &[u8; 8]) -> HotpOutput {
    let hmac_value = hmacsha1::hmac_sha1(key, counter);
    let dbc = sbits(&hmac_value);
    HotpOutput{ code: dbc % 10u32.pow(desired_code_length as u32), length: desired_code_length }
}

fn offset(b: &[u8; hmacsha1::SHA1_DIGEST_BYTES]) -> usize {
    (b.last().unwrap() & 0xf) as usize
}

fn sbits(bits: &[u8; hmacsha1::SHA1_DIGEST_BYTES]) -> u32 {
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
