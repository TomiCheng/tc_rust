use std::io::Write;

use tc_algo::params::{KeyOwned, RsaKeyGenParams};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
use tc_x509::operator::{
    DefaultDigestCalculator, DefaultMacCalculator, DefaultSignatureCalculator, StreamCalculator,
};

#[test]
fn a_message_written_in_pieces_is_signed_as_the_whole_message() {
    let algo = DefaultAlgoBuilder::default().build();
    let pair = algo
        .key_pair_generator()
        .generate_by_name_with("RSA", &RsaKeyGenParams::new(1024))
        .unwrap();

    let mut signer = algo.signer().get_by_name("SHA-256withRSA").unwrap();
    signer.init(pair.private()).unwrap();
    let mut calculator: Box<dyn StreamCalculator<_>> =
        Box::new(DefaultSignatureCalculator::new(signer));
    calculator.write_all(b"to be ").unwrap();
    calculator.write_all(b"signed").unwrap();
    let signature = calculator.result().collect().unwrap();

    let mut verifier = algo.signer().get_by_name("SHA-256withRSA").unwrap();
    verifier.init(pair.public()).unwrap();
    verifier.update(b"to be signed").unwrap();
    assert!(verifier.verify_signature(&signature).unwrap());
}

#[test]
fn a_signer_that_was_not_initialized_fails_the_write() {
    let algo = DefaultAlgoBuilder::default().build();
    let signer = algo.signer().get_by_name("SHA-256withRSA").unwrap();

    let mut calculator = DefaultSignatureCalculator::new(signer);
    assert!(calculator.write_all(b"data").is_err());
}

#[test]
fn a_message_written_in_pieces_gets_the_tag_of_the_whole_message() {
    let algo = DefaultAlgoBuilder::default().build();
    let key = KeyOwned::new(vec![0x0b; 20]);

    let mut expected = algo.mac().get_by_name("HMAC-SHA256").unwrap();
    expected.init(&key).unwrap();
    expected.update(b"Hi There").unwrap();
    let expected = expected.finalize().unwrap();

    let mut mac = algo.mac().get_by_name("HMAC-SHA256").unwrap();
    mac.init(&key).unwrap();
    let mut calculator = Box::new(DefaultMacCalculator::new(mac));
    calculator.write_all(b"Hi ").unwrap();
    calculator.write_all(b"There").unwrap();

    assert_eq!(calculator.result().collect().unwrap(), expected);
}

#[test]
fn a_mac_that_was_not_initialized_fails_the_write() {
    let algo = DefaultAlgoBuilder::default().build();
    let mac = algo.mac().get_by_name("HMAC-SHA256").unwrap();

    let mut calculator = DefaultMacCalculator::new(mac);
    assert!(calculator.write_all(b"data").is_err());
}

#[test]
fn a_message_written_in_pieces_gets_the_hash_of_the_whole_message() {
    // SHA-256 of "abc", from FIPS 180-4's examples
    const ABC_HASH: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let algo = DefaultAlgoBuilder::default().build();
    let digest = algo.digest().get_by_name("SHA-256").unwrap();

    let mut calculator = Box::new(DefaultDigestCalculator::new(digest));
    calculator.write_all(b"a").unwrap();
    calculator.write_all(b"bc").unwrap();

    assert_eq!(calculator.result().collect().unwrap(), ABC_HASH);
}
