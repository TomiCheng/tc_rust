use tc_algo::params::{AnyKeyParams, AnyParams, SecretKey};

// FIPS 197, appendix C.1: the AES-128 key
const AES_128_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[test]
fn an_aes_key_goes_into_the_params_as_a_secret_key() {
    let params = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(AES_128_KEY.to_vec())));
    let AnyKeyParams::Secret(secret) = &params.key else {
        panic!("not a secret key");
    };
    assert_eq!(secret.key, AES_128_KEY);
}

#[test]
fn any_length_is_accepted_as_the_algorithm_checks_it_at_init() {
    for length in [0, 1, 15, 17, 1000] {
        assert_eq!(SecretKey::new(vec![0; length]).key.len(), length);
    }
}

#[test]
fn a_clone_is_independent_of_the_original() {
    let original = SecretKey::new(AES_128_KEY.to_vec());
    let mut copy = original.clone();
    copy.key[0] ^= 0xff;
    assert_eq!(original.key, AES_128_KEY);
    assert_ne!(copy.key, AES_128_KEY);
}

#[test]
fn debug_shows_the_length_but_no_key_bytes() {
    let params = AnyParams::new(AnyKeyParams::Secret(SecretKey::new(vec![0xab; 16])));
    let shown = format!("{params:?}");
    assert_eq!(
        shown,
        "AnyParams { key: Secret(SecretKey { len: 16, .. }), op: AnyOpParams }"
    );
    assert!(!shown.contains("171"));
}

#[test]
fn a_secret_key_can_be_cloned_and_sent_between_threads() {
    fn assert_traits<T: Clone + Send + Sync + 'static>() {}
    assert_traits::<SecretKey>();
}
