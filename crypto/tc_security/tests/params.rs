//! `AnyParams`：每個 variant 對應 BC 的一個參數類別，各引擎的參數 trait 依 variant 取值。

use tc_aead_cipher::{InitialAadParams, MacSizeParams, NonceParams};
use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_key_wrap::IvOptParams;
use tc_security::params::AnyParams;

#[test]
fn a_key_alone_carries_no_iv() {
    let params = AnyParams::new(vec![1; 16]);
    assert_eq!(KeyParams::key(&params), [1; 16]);
    assert!(IvParams::iv(&params).is_empty());
    assert_eq!(params.iv_opt(), None);
}

#[test]
fn an_iv_wraps_the_parameters_and_the_key_is_found_inside() {
    let params = AnyParams::new(vec![1; 16]).with_iv(vec![2; 12]);
    assert!(matches!(&params, AnyParams::WithIv { parameters, .. }
        if matches!(**parameters, AnyParams::Key { .. })));
    assert_eq!(KeyParams::key(&params), [1; 16]);
    assert_eq!(IvParams::iv(&params), [2; 12]);
    assert_eq!(params.iv_opt(), Some(&[2; 12][..]));
}

#[test]
fn aead_parameters_give_their_nonce_and_associated_text_and_the_tag_size_in_bytes() {
    let params = AnyParams::aead(vec![1; 16], 96, vec![2; 12], b"header".to_vec());
    assert_eq!(KeyParams::key(&params), [1; 16]);
    assert_eq!(params.nonce(), [2; 12]);
    assert_eq!(params.initial_aad(), b"header");
    assert_eq!(params.mac_size(), 12);
}

#[test]
fn a_tag_size_that_is_not_whole_bytes_reports_zero_for_init_to_reject() {
    let params = AnyParams::aead(vec![1; 16], 100, vec![2; 12], Vec::new());
    assert_eq!(params.mac_size(), 0);
}

#[test]
fn an_iv_is_no_aead_nonce_and_gives_no_tag_size_for_init_to_reject() {
    // 不同於 BC：AEAD 一定要用 `Aead`，tag 長度不靠預設值
    let params = AnyParams::new(vec![1; 16]).with_iv(vec![2; 12]);
    assert!(params.nonce().is_empty());
    assert_eq!(params.mac_size(), 0);
    assert!(params.initial_aad().is_empty());
}

#[test]
fn parameters_without_an_iv_or_nonce_report_empty_ones_for_init_to_reject() {
    let params = AnyParams::new(vec![1; 16]);
    assert!(params.nonce().is_empty());
    assert!(params.initial_aad().is_empty());
}

#[cfg(feature = "rsa")]
#[test]
fn an_rsa_key_carries_no_symmetric_key_or_iv() {
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_rsa::{RsaKeyGenerationParamsOwned, RsaKeyGenerator};

    let mut generator = RsaKeyGenerator::new();
    generator
        .init(RsaKeyGenerationParamsOwned::new(rand::rng()).with_strength(1024))
        .unwrap();
    let (public, _) = generator.generate_key_pair().unwrap();

    let params = AnyParams::rsa(public);
    assert!(matches!(params, AnyParams::Rsa { .. }));
    assert!(KeyParams::key(&params).is_empty());
    assert!(IvParams::iv(&params).is_empty());
}

#[cfg(feature = "aes")]
#[test]
fn parameter_generators_are_found_by_cipher_name_or_oid() {
    use tc_security::SecurityError;
    use tc_security::params;

    let name_of = |name: &str| params::get_by_name(name).map(|entry| entry.name());
    assert_eq!(name_of("aes/cbc/pkcs7padding"), Ok("AES/CBC/PKCS7PADDING"));
    assert_eq!(name_of("AES"), Ok("AES/ECB/PKCS7PADDING"));
    assert_eq!(name_of("AES/GCM"), Ok("AES/GCM/NOPADDING"));
    assert_eq!(name_of("2.16.840.1.101.3.4.1.46"), Ok("AES/GCM/NOPADDING"));
    assert_eq!(
        params::get_by_oid(&"2.16.840.1.101.3.4.1.2".parse().unwrap()).map(|entry| entry.name()),
        Ok("AES/CBC/PKCS7PADDING")
    );
    assert_eq!(name_of("AES/XYZ"), Err(SecurityError::UnknownCipher));
}
