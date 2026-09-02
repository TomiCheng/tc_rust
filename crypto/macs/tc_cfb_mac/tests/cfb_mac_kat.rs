use tc_cfb_mac::{CfbMac, Params};
use tc_des::DesEngine;
use tc_macs::{Mac, MacInit};

const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];

#[test]
fn matches_the_bouncy_castle_cfb8_mac_vectors() {
    let mut mac = CfbMac::new(DesEngine::new()).unwrap();
    mac.init(&Params::new(&KEY).with_iv(&IV)).unwrap();
    mac.update(b"7654321 Now is the time for ").unwrap();
    let mut output = [0_u8; 4];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0xcd, 0x64, 0x74, 0x03]);
}
