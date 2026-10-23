use tc_md::Md5Digest;
use tc_pbe::{
    PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S1, pkcs5_password_to_bytes,
};
use tc_sha::Sha1Digest;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

const SALT: &str = "7d60435f02e9e0ae";

#[test]
fn pbe_with_sha1_and_des_gives_the_key_and_iv_of_bcs_pbe_test() {
    // BC PBETest：PBEWithSHA1AndDES 解得開以這組 DES 金鑰與 IV 加密的資料
    let password = pkcs5_password_to_bytes("password");
    let salt = hex(SALT);
    let mut generator = Pkcs5S1::new(Sha1Digest::new());
    generator
        .init(&PbeParamsRef::new(&password, &salt, 2048))
        .unwrap();
    let (mut key, mut iv) = ([0; 8], [0; 8]);
    generator.derive_key_and_iv(&mut key, &mut iv).unwrap();
    assert_eq!(key[..], hex("30e69252758e5346"));
    assert_eq!(iv[..], hex("7c1c1ab9c454a688"));
}

#[test]
fn the_output_is_cut_from_the_front_of_the_last_digest() {
    // 以 Python hashlib 照 RFC 8018 5.1 另外算出的 MD5 結果
    let password = pkcs5_password_to_bytes("password");
    let salt = hex(SALT);
    let mut generator = Pkcs5S1::new(Md5Digest::new());
    generator
        .init(&PbeParamsRef::new(&password, &salt, 2048))
        .unwrap();
    let mut whole = [0; 16];
    generator.derive_key(&mut whole).unwrap();
    assert_eq!(whole[..], hex("b880f25bc30b3e9bcfa9ec1f4d74d689"));

    let (mut key, mut iv) = ([0; 8], [0; 8]);
    generator.derive_key_and_iv(&mut key, &mut iv).unwrap();
    assert_eq!([key, iv].concat(), whole);

    let mut mac_key = [0; 10];
    generator.derive_mac_key(&mut mac_key).unwrap();
    assert_eq!(mac_key[..], whole[..10]);
}

#[test]
fn one_iteration_is_a_single_hash_of_password_and_salt() {
    let password = pkcs5_password_to_bytes("password");
    let salt = hex(SALT);
    let mut generator = Pkcs5S1::new(Sha1Digest::new());
    generator
        .init(&PbeParamsRef::new(&password, &salt, 1))
        .unwrap();
    let mut key = [0; 20];
    generator.derive_key(&mut key).unwrap();
    assert_eq!(key[..], hex("3a9fc16526a31b3ce7e3fa1ba025de48b0e4decf"));
}

#[test]
fn asking_for_more_than_one_digest_fails() {
    let mut generator = Pkcs5S1::new(Md5Digest::new());
    generator
        .init(&PbeParamsRef::new(b"pw", b"salt", 10))
        .unwrap();
    assert_eq!(
        generator.derive_key(&mut [0; 17]),
        Err(PbeError::OutputTooLong)
    );
    assert_eq!(
        generator.derive_key_and_iv(&mut [0; 16], &mut [0; 1]),
        Err(PbeError::OutputTooLong)
    );
}

#[test]
fn a_zero_iteration_count_is_refused_and_keeps_the_previous_parameters() {
    let mut generator = Pkcs5S1::new(Md5Digest::new());
    assert_eq!(
        generator.derive_key(&mut [0; 8]),
        Err(PbeError::NotInitialised)
    );
    generator
        .init(&PbeParamsRef::new(b"pw", b"salt", 10))
        .unwrap();
    let mut before = [0; 8];
    generator.derive_key(&mut before).unwrap();

    assert_eq!(
        generator.init(&PbeParamsRef::new(b"other", b"salt", 0)),
        Err(PbeError::InvalidIterationCount(0))
    );
    let mut after = [0; 8];
    generator.derive_key(&mut after).unwrap();
    assert_eq!(after, before);
}
