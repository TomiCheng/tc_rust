use tc_algo::params::{KeyOwned, RsaKeyGenParams};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};
use tc_x509::X509Error;
use tc_x509::operator::{
    BlockResult, DefaultDigestResult, DefaultMacResult, DefaultSignatureResult, SimpleBlockResult,
};

// SHA-256 of "abc", from FIPS 180-4's examples
const ABC_HASH: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

#[test]
fn a_digest_result_collects_the_hash_of_what_the_digest_took_in() {
    let algo = DefaultAlgoBuilder::default().build();
    let mut digest = algo.digest().get_by_name("SHA-256").unwrap();
    digest.try_update(b"abc").unwrap();

    let mut result = DefaultDigestResult::new(digest);
    assert_eq!(result.max_result_length(), 32);
    assert_eq!(result.collect().unwrap(), ABC_HASH);
}

#[test]
fn a_digest_result_refuses_a_short_output_instead_of_panicking() {
    let algo = DefaultAlgoBuilder::default().build();
    let digest = algo.digest().get_by_name("SHA-256").unwrap();

    let mut result = DefaultDigestResult::new(digest);
    let error = result.collect_into(&mut [0; 31]).unwrap_err();
    assert!(matches!(error, X509Error::Algo(error) if error.kind() == ErrorKind::DataLength));
}

#[test]
fn a_mac_result_collects_the_tag_the_mac_would_give() {
    let algo = DefaultAlgoBuilder::default().build();
    let key = KeyOwned::new(vec![0x0b; 20]);

    let mut expected = algo.mac().get_by_name("HMAC-SHA256").unwrap();
    expected.init(&key).unwrap();
    expected.update(b"Hi There").unwrap();
    let expected = expected.finalize().unwrap();

    let mut mac = algo.mac().get_by_name("HMAC-SHA256").unwrap();
    mac.init(&key).unwrap();
    mac.update(b"Hi There").unwrap();
    let mut result = DefaultMacResult::new(mac);

    assert_eq!(result.max_result_length(), 32);
    assert_eq!(result.collect().unwrap(), expected);
}

#[test]
fn a_signature_result_collects_a_signature_that_verifies() {
    let algo = DefaultAlgoBuilder::default().build();
    let pair = algo
        .key_pair_generator()
        .generate_by_name_with("RSA", &RsaKeyGenParams::new(1024))
        .unwrap();

    let mut signer = algo.signer().get_by_name("SHA-256withRSA").unwrap();
    signer.init(pair.private()).unwrap();
    signer.update(b"to be signed").unwrap();
    let mut result = DefaultSignatureResult::new(signer);
    let signature = result.collect().unwrap();

    let mut verifier = algo.signer().get_by_name("SHA-256withRSA").unwrap();
    verifier.init(pair.public()).unwrap();
    verifier.update(b"to be signed").unwrap();
    assert!(verifier.verify_signature(&signature).unwrap());
}

#[test]
fn a_simple_result_gives_the_same_bytes_each_time_and_refuses_a_short_output() {
    let mut result = SimpleBlockResult::new(vec![1, 2, 3]);

    assert_eq!(result.max_result_length(), 3);
    assert_eq!(result.collect().unwrap(), [1, 2, 3]);
    assert_eq!(result.collect().unwrap(), [1, 2, 3]);

    let error = result.collect_into(&mut [0; 2]).unwrap_err();
    assert!(matches!(error, X509Error::OutputTooShort));
}
