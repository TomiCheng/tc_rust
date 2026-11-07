use std::io::Write;

use tc_algo_v2::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};
use tc_asn1::Asn1Oid;
use tc_operator_v2::digest::{Asn1DigestFactory, DigestFactory};

const SHA256: &str = "2.16.840.1.101.3.4.2.1";

// SHA-256 of "abc", from FIPS 180-4's examples
const ABC_HASH: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().unwrap()
}

#[test]
fn a_name_gives_the_algorithm_identifier_without_parameters_and_the_size() {
    let algo = DefaultAlgoBuilder::default().build();
    let factory = Asn1DigestFactory::new(algo.as_ref(), "sha-256").unwrap();

    assert_eq!(factory.algorithm().algorithm(), &oid(SHA256));
    assert!(factory.algorithm().parameters().is_none());
    assert_eq!(factory.digest_size(), 32);
}

#[test]
fn an_oid_gives_the_same_hash_as_a_name() {
    let algo = DefaultAlgoBuilder::default().build();
    let by_name = Asn1DigestFactory::new(algo.as_ref(), "SHA-256").unwrap();
    let by_oid = Asn1DigestFactory::with_oid(algo.as_ref(), &oid(SHA256)).unwrap();

    assert_eq!(by_name.digest(b"abc").unwrap(), ABC_HASH);
    assert_eq!(by_oid.digest(b"abc").unwrap(), ABC_HASH);
}

#[test]
fn a_message_written_in_pieces_gives_the_hash_of_the_whole_message() {
    let algo = DefaultAlgoBuilder::default().build();
    let factory = Asn1DigestFactory::new(algo.as_ref(), "SHA-256").unwrap();

    let mut calculator = factory.create_calculator().unwrap();
    calculator.write_all(b"a").unwrap();
    calculator.write_all(b"bc").unwrap();

    assert_eq!(calculator.finish(), ABC_HASH);
}

#[test]
fn a_calculator_starts_the_next_message_after_finish() {
    let algo = DefaultAlgoBuilder::default().build();
    let factory = Asn1DigestFactory::new(algo.as_ref(), "SHA-256").unwrap();

    let mut calculator = factory.create_calculator().unwrap();
    calculator.write_all(b"first message").unwrap();
    calculator.finish();
    calculator.write_all(b"abc").unwrap();

    assert_eq!(calculator.finish(), ABC_HASH);
}

#[test]
fn an_unknown_name_or_oid_is_an_unknown_digest() {
    let algo = DefaultAlgoBuilder::default().build();

    let error = Asn1DigestFactory::new(algo.as_ref(), "NOPE").err().unwrap();
    assert_eq!(error.kind(), ErrorKind::UnknownDigest);

    let error = Asn1DigestFactory::with_oid(algo.as_ref(), &oid("1.2.3"))
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::UnknownDigest);
}
