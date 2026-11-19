use tc_algo::params::{generate::RsaKeyGenParams, key::RsaKey, key::RsaKeyParams};
use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

#[test]
fn generates_a_matching_rsa_key_pair() {
    let tag = PublicKeyAlgorithmTag::RsaGeneral;
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator.key_pair_generator().get_by_algorithm(tag).unwrap();
    let (public, private) = generator.generate(&RsaKeyGenParams::new(3072)).unwrap();

    assert_eq!(public.algorithm(), tag);
    assert_eq!(private.algorithm(), tag);
    let public = public.key().as_any().downcast_ref::<RsaKey>().unwrap();
    let private = private.key().as_any().downcast_ref::<RsaKey>().unwrap();
    assert_eq!(public.modulus().bits(), 3072);
    assert_eq!(public.modulus(), private.modulus());
}
