#![cfg(feature = "rsa")]

use tc_algo_old::{AnyKeyParams, AnyParams, AnyPrivateKey, AnyPublicKey};
use tc_bigint::PaddedBigUint;
use tc_rsa::{RsaKey, RsaKeyOwned};

// A toy key, n = 323 = 17 * 19: the params are plain data, so nothing here checks it
fn rsa_key(is_private: bool, exponent: u32) -> RsaKey {
    RsaKeyOwned::new(
        is_private,
        PaddedBigUint::from(323u32),
        PaddedBigUint::from(exponent),
    )
    .into()
}

#[test]
fn an_rsa_key_goes_into_the_params_as_a_private_or_a_public_key() {
    let private = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::Rsa(rsa_key(
        true, 173,
    ))));
    let public = AnyParams::new(AnyKeyParams::Public(AnyPublicKey::Rsa(rsa_key(false, 5))));
    assert!(matches!(
        private.key,
        AnyKeyParams::Private(AnyPrivateKey::Rsa(_))
    ));
    assert!(matches!(
        public.key,
        AnyKeyParams::Public(AnyPublicKey::Rsa(_))
    ));
}

#[test]
fn debug_shows_the_algorithm_but_no_key_values() {
    let private = AnyParams::new(AnyKeyParams::Private(AnyPrivateKey::Rsa(rsa_key(
        true, 173,
    ))));
    let shown = format!("{private:?}");
    assert_eq!(
        shown,
        "AnyParams { key: Private(Rsa(..)), op: AnyOpParams { iv: None, tag_len: None, aad: None } }"
    );
    assert!(!shown.contains("173"));
}

#[test]
fn the_params_can_be_cloned_and_sent_between_threads() {
    fn assert_traits<T: Clone + Send + Sync + 'static>() {}
    assert_traits::<AnyParams>();
    assert_traits::<AnyPrivateKey>();
    assert_traits::<AnyPublicKey>();
}
