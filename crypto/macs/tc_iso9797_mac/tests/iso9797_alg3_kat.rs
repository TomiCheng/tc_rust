use tc_iso9797_mac::{Iso9797Alg3Mac, Params};
use tc_macs::{Mac, MacInit};

#[test]
fn matches_the_bouncy_castle_retail_mac_vector() {
    let key = [
        0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57, 0x01, 0x31, 0xd9, 0x61, 0x9d, 0xc1, 0x37,
        0x6e,
    ];
    let mut mac = Iso9797Alg3Mac::new();
    mac.init(&Params::new(&key)).unwrap();
    for chunk in b"Hello World !!!!".chunks(3) {
        mac.update(chunk).unwrap();
    }

    let mut output = [0_u8; 8];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0xf0, 0x9b, 0x85, 0x62, 0x13, 0xba, 0xb8, 0x3b]);

    mac.update(b"Hello World !!!!").unwrap();
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0xf0, 0x9b, 0x85, 0x62, 0x13, 0xba, 0xb8, 0x3b]);
}
