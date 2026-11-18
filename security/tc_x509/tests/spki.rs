use std::any::Any;

use tc_algo::Params;
use tc_algo::generate::KeyPair;
use tc_asn1::{Asn1BitString, Decode, DecodingOptions};
use tc_asn1_pkcs::RsaPublicKey;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_x509::operator::params::{RsaKey, RsaKeyGenParams, RsaKeyParams, X25519PublicKey};
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

fn rsa_pair(oper: &dyn X509Operator) -> KeyPair {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    key_gen.generate().unwrap()
}

#[test]
fn an_rsa_public_key_becomes_rsa_encryption_with_its_modulus_and_exponent() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let pair = rsa_pair(oper.as_ref());

    let spki = oper.spki().encode(pair.public()).unwrap();

    let algorithm = spki.algorithm();
    assert_eq!(algorithm.algorithm().to_string(), "1.2.840.113549.1.1.1");
    assert!(algorithm.parameters().is_some());

    let (_, key) = RsaPublicKey::decode(
        spki.subject_public_key().as_bytes(),
        &DecodingOptions::default(),
    )
    .unwrap();
    assert_eq!(key.modulus().as_unsigned_bytes().unwrap().len(), 128);
    assert_eq!(
        key.public_exponent().as_unsigned_bytes().unwrap(),
        [1, 0, 1]
    );
}

#[test]
fn a_private_key_is_refused() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let pair = rsa_pair(oper.as_ref());

    let error = oper.spki().encode(pair.private()).unwrap_err();
    assert!(matches!(error, X509Error::NotPublicKey));
}

struct OtherKey;

impl Params for OtherKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn a_key_no_row_knows_is_an_unknown_public_key() {
    let oper = DefaultX509OperatorBuilder::default().build();

    let error = oper.spki().encode(&OtherKey).unwrap_err();
    assert!(matches!(error, X509Error::UnknownPublicKey));
}

#[test]
fn an_rsa_spki_reads_back_as_the_public_key_it_was_made_from() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let pair = rsa_pair(oper.as_ref());
    let original = pair.public().as_any().downcast_ref::<RsaKey>().unwrap();

    let spki = oper.spki().encode(pair.public()).unwrap();
    let key = oper.spki().decode(&spki).unwrap();

    let key = key.as_any().downcast_ref::<RsaKey>().unwrap();
    assert_eq!(key.modulus(), original.modulus());
    assert_eq!(key.exponent(), original.exponent());
    assert_eq!(oper.spki().encode(key).unwrap(), spki);
}

#[test]
fn an_spki_of_an_algorithm_no_row_knows_is_an_unknown_public_key() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let spki = SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
        Asn1BitString::from_bytes(&[0x30, 0x00]),
    );

    let error = oper.spki().decode(&spki).err().unwrap();
    assert!(matches!(error, X509Error::UnknownPublicKey));
}

#[test]
fn an_x25519_public_key_becomes_id_x25519_with_its_32_bytes_and_reads_back() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let mut key_gen = oper.key_pair_generator().get_by_name("X25519").unwrap();
    let pair = key_gen.generate().unwrap();
    let original = pair
        .public()
        .as_any()
        .downcast_ref::<X25519PublicKey>()
        .unwrap();

    let spki = oper.spki().encode(pair.public()).unwrap();
    assert_eq!(spki.algorithm().algorithm().to_string(), "1.3.101.110");
    assert!(spki.algorithm().parameters().is_none());
    assert_eq!(spki.subject_public_key().as_bytes(), original.u());

    let key = oper.spki().decode(&spki).unwrap();
    let key = key.as_any().downcast_ref::<X25519PublicKey>().unwrap();
    assert_eq!(key.u(), original.u());
}

#[test]
fn an_x25519_spki_with_parameters_or_a_short_key_is_invalid() {
    let oper = DefaultX509OperatorBuilder::default().build();
    for spki in [
        SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::with_null("1.3.101.110".parse().unwrap()),
            Asn1BitString::from_bytes(&[9; 32]),
        ),
        SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new("1.3.101.110".parse().unwrap()),
            Asn1BitString::from_bytes(&[9; 31]),
        ),
    ] {
        let error = oper.spki().decode(&spki).err().unwrap();
        assert!(matches!(error, X509Error::InvalidPublicKey));
    }
}
