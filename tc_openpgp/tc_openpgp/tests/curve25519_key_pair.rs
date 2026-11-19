use tc_algo::params::key::{
    Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey, X25519PublicKey,
};
use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

#[test]
fn generates_matching_ed25519_keys() {
    let tag = PublicKeyAlgorithmTag::Ed25519;
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator.key_pair_generator().get_by_algorithm(tag).unwrap();
    let (public, private) = generator.generate_without_params().unwrap();
    assert_eq!(public.algorithm(), tag);
    assert_eq!(private.algorithm(), tag);
    let public = public
        .key()
        .as_any()
        .downcast_ref::<Ed25519PublicKey>()
        .unwrap();
    let private = private
        .key()
        .as_any()
        .downcast_ref::<Ed25519PrivateKey>()
        .unwrap();
    assert_eq!(&private.generate_public_key(), public);
}

#[test]
fn generates_matching_x25519_keys() {
    let tag = PublicKeyAlgorithmTag::X25519;
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator.key_pair_generator().get_by_algorithm(tag).unwrap();
    let (public, private) = generator.generate_without_params().unwrap();
    assert_eq!(public.algorithm(), tag);
    assert_eq!(private.algorithm(), tag);
    let public = public
        .key()
        .as_any()
        .downcast_ref::<X25519PublicKey>()
        .unwrap();
    let private = private
        .key()
        .as_any()
        .downcast_ref::<X25519PrivateKey>()
        .unwrap();
    assert_eq!(&private.generate_public_key(), public);
}
