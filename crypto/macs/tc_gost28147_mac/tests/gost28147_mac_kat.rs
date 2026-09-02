use tc_gost28147::s_box;
use tc_gost28147_mac::{Gost28147Mac, Params};
use tc_macs::{Mac, MacInit};

#[test]
fn matches_the_bouncy_castle_vector() {
    let key = [
        0x6d, 0x14, 0x5d, 0xc9, 0x93, 0xf4, 0x01, 0x9e, 0x10, 0x42, 0x80, 0xdf, 0x6f, 0xcd, 0x8c,
        0xd8, 0xe0, 0x1e, 0x10, 0x1e, 0x4c, 0x11, 0x3d, 0x7e, 0xc4, 0xf4, 0x69, 0xce, 0x6d, 0xcd,
        0x9e, 0x49,
    ];
    let message = b"what do ya want for nothing?";
    let mut mac = Gost28147Mac::new();
    mac.init(&Params::new(&key).with_s_box(&s_box::E_A))
        .unwrap();
    for chunk in message.chunks(5) {
        mac.update(chunk).unwrap();
    }

    let mut output = [0_u8; 4];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0x93, 0x46, 0x8a, 0x46]);
}
