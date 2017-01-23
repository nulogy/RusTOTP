extern crate crypto;

use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;

pub fn hmac_sha1(k : &[u8], c : &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha1::new(), k);
    for i in 0..c.len() {
        hmac.input(&c[i..i+1]);
    }
    let result = hmac.result();
    result.code().to_vec()
}
