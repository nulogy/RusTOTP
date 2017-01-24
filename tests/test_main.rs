extern crate rfc6238;

use rfc6238::{hotp, totp};

pub fn format_hex(s: &[u8]) -> String {
    let mut human_representation: Vec<String> = Vec::new();

    for c in s.iter() {
        human_representation.push(format!("{:02x}", c))
    }
    format!("0x{}", human_representation.join(""))
}


#[test]
fn hotp_conforms_to_example_1_given_in_rfc6238() {
    let key = "12345678901234567890".as_bytes();
    let mut c_buffer = [0; 8];
    c_buffer[7] = 1;
    let totp_value = hotp(8, key, &c_buffer);
    assert_eq!(94287082, totp_value.code);
}

#[test]
fn hotp_conforms_to_example_4_given_in_rfc6238() {
    let key = "12345678901234567890".as_bytes();
    let c_buffer = [
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x35,
        0x23,
        0xec
    ];
    let totp_value = hotp(8, key, &c_buffer);
    assert_eq!(07081804, totp_value.code);
}

#[test]
fn hotp_conforms_to_example_7_given_in_rfc6238() {
    let key = "12345678901234567890".as_bytes();
    let c_buffer = [
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x35,
        0x23,
        0xed
    ];
    let totp_value = hotp(8, key, &c_buffer);
    assert_eq!(14050471, totp_value.code);
}

#[test]
fn totp_conforms_to_example_1_given_in_rfc6238() {
    let key = "12345678901234567890".as_bytes();
    let current_time = 59;
    let totp_value = totp(8, 30, key, current_time);
    assert_eq!(94287082, totp_value.code);
}
