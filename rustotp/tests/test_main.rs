extern crate rustotp;

#[test]
fn totp_conforms_to_example_1_given_in_rfc6238() {
    let key = "12345678901234567890".as_bytes();
    let current_time = 59;
    let totp_value = rustotp::totp(8, 30, key, current_time);
    assert_eq!(94287082, totp_value.code);
}
