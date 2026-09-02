use tc_cbc_mac::{CbcMac, Params};
use tc_des::DesEngine;
use tc_macs::{Mac, MacInit};
use tc_pkcs7_pad::Pkcs7Padding;

const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
const INPUT1: &[u8] = b"7654321 Now is the time for ";
const INPUT2: &[u8] = b"7654321 ";

#[test]
fn matches_the_fips_and_bouncy_castle_vectors() {
    let mut mac = CbcMac::new(DesEngine::new()).unwrap();
    mac.init(&Params::new(&KEY)).unwrap();
    mac.update(INPUT1).unwrap();
    let mut output = [0_u8; 4];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0xf1, 0xd3, 0x0f, 0x68]);

    mac.init(&Params::new(&KEY).with_iv(&IV)).unwrap();
    mac.update(INPUT1).unwrap();
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0x58, 0xd2, 0xe7, 0x7e]);
}

#[test]
fn matches_bouncy_castle_pkcs7_padding_vectors() {
    let mut mac = CbcMac::with_padding(DesEngine::new(), Pkcs7Padding::new()).unwrap();
    mac.init(&Params::new(&KEY)).unwrap();
    mac.update(INPUT2).unwrap();
    let mut output = [0_u8; 4];
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0x18, 0x8f, 0xbd, 0xd5]);

    mac.update(INPUT1).unwrap();
    mac.do_final(&mut output).unwrap();
    assert_eq!(output, [0x70, 0x45, 0xee, 0xcd]);
}
