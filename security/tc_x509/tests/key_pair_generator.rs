use tc_x509::operator::params::{RsaKey, RsaKeyGenParams, RsaKeyParams};
use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

#[test]
fn the_operator_generates_an_rsa_key_pair_without_algo_set() {
    let oper = DefaultX509OperatorBuilder::default().build();

    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let pair = key_gen.generate().unwrap();

    let public = pair.public().as_any().downcast_ref::<RsaKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<RsaKey>().unwrap();
    assert_eq!(public.modulus(), private.modulus());
    assert_eq!(public.modulus().bits(), 1024);
}
