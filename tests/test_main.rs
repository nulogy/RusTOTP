extern crate rfc6238;

fn format_hex(s: &[u8]) -> String {
    let mut human_representation: Vec<String> = Vec::new();
    
    for c in s.iter() {
        human_representation.push(format!("Ox{:x}", c))
    }
    format!("{}", human_representation.join(", "))
}

#[test]
fn it_works() {
    let counter : &[u8] = &[ 0x00; 8 ];
    let result = rfc6238::hmac_sha1(&[0x0b; 20], "Hi There".as_bytes());
    println!("{}", format_hex(result.as_slice()));
    assert!(false);
}
