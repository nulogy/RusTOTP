extern crate rfc6238;

fn format_hex(s: &[u8]) -> String {
    let mut human_representation: Vec<String> = Vec::new();
    
    for c in s.iter() {
        human_representation.push(format!("{:02x}", c))
    }
    format!("0x{}", human_representation.join(""))
}

#[test]
fn it_works() {
    let counter : &[u8] = &[ 0x00; 8 ];
    println!("HMAC-SHA-1:");
    println!("================================================================================");
    let example : &[u8] = &[
        0x1f,
        0x86,
        0x98,
        0x69,
        0x0e,
        0x02,
        0xca,
        0x16,
        0x61,
        0x85,
        0x50,
        0xef,
        0x7f,
        0x19,
        0xda,
        0x8e,
        0x94,
        0x5b,
        0x55,
        0x5a
    ];

    println!("HMAC SHA-1: {}", format_hex(example));
    println!("================================================================================");

    println!("Offset index: {}", rfc6238::offset(example));
    println!("================================================================================");

    println!("P: {:x}", rfc6238::sbits(example));
    println!("================================================================================");

    println!("HOTP Value: {}", rfc6238::hotp(rfc6238::sbits(example)));
    println!("================================================================================");
    assert!(false);
}
