use tc_block_modes::KeyWithIvRef;
use tc_iso9797_mac::{InitError, Iso9797Alg3Mac};
use tc_macs::{Mac, MacInit};

const KEY: [u8; 16] = [
    0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57, 0x01, 0x31, 0xd9, 0x61, 0x9d, 0xc1, 0x37, 0x6e,
];

#[test]
fn matches_the_bouncy_castle_retail_mac_vector_under_a_zero_iv() {
    let mut mac = Iso9797Alg3Mac::new();
    mac.init(&KeyWithIvRef::new(&KEY, &[0; 8])).unwrap();
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

#[test]
fn the_iv_must_be_exactly_one_des_block() {
    let mut mac = Iso9797Alg3Mac::new();
    for length in [0, 7, 9, 16] {
        assert_eq!(
            mac.init(&KeyWithIvRef::new(&KEY, &vec![0; length])),
            Err(InitError::InvalidIvLength(length))
        );
    }
}

#[test]
fn display_writes_the_bouncy_castle_name() {
    assert_eq!(Iso9797Alg3Mac::new().to_string(), "ISO9797Alg3");
}
