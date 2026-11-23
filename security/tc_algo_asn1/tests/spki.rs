use std::any::Any;

use tc_algo::Params;
use tc_algo::generate::KeyPair;
use tc_algo::params::{
    generate::EcKeyGenParams, generate::RsaKeyGenParams, key::RsaKey, key::RsaKeyParams,
    key::X448PrivateKey, key::X448PublicKey, key::X25519PublicKey,
};
use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_algo_asn1::{AlgoAsn1, AlgoAsn1Builder, AlgoAsn1Error, DefaultAlgoAsn1Builder};
use tc_asn1::{Asn1BitString, Asn1Object, Decode, DecodingOptions};
use tc_asn1_pkcs::{PrivateKeyInfo, RsaPublicKey};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

fn algo() -> Box<dyn Algo> {
    DefaultAlgoBuilder::default().build()
}

fn rsa_pair() -> KeyPair {
    let mut key_gen = algo().key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    key_gen.generate().unwrap()
}

#[test]
fn an_rsa_public_key_becomes_rsa_encryption_with_its_modulus_and_exponent() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = rsa_pair();

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
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = rsa_pair();

    let error = oper.spki().encode(pair.private()).unwrap_err();
    assert!(matches!(error, AlgoAsn1Error::NotPublicKey));
}

struct OtherKey;

impl Params for OtherKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn a_key_no_row_knows_is_an_unknown_public_key() {
    let oper = DefaultAlgoAsn1Builder::default().build();

    let error = oper.spki().encode(&OtherKey).unwrap_err();
    assert!(matches!(error, AlgoAsn1Error::UnknownPublicKey));
}

#[test]
fn an_rsa_spki_reads_back_as_the_public_key_it_was_made_from() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = rsa_pair();
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
    let oper = DefaultAlgoAsn1Builder::default().build();
    let spki = SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
        Asn1BitString::from_bytes(&[0x30, 0x00]),
    );

    let error = oper.spki().decode(&spki).err().unwrap();
    assert!(matches!(error, AlgoAsn1Error::UnknownPublicKey));
}

#[test]
fn an_x25519_public_key_becomes_id_x25519_with_its_32_bytes_and_reads_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let mut key_gen = algo().key_pair_generator().get_by_name("X25519").unwrap();
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
    let oper = DefaultAlgoAsn1Builder::default().build();
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
        assert!(matches!(error, AlgoAsn1Error::InvalidPublicKey));
    }
}

fn ec_spki(oper: &dyn AlgoAsn1, curve: &str) -> SubjectPublicKeyInfo {
    let mut key_gen = algo().key_pair_generator().get_by_name("EC").unwrap();
    key_gen.init(&EcKeyGenParams::new(curve)).unwrap();
    let pair = key_gen.generate().unwrap();
    oper.spki().encode(pair.public()).unwrap()
}

fn curve_oid(spki: &SubjectPublicKeyInfo) -> String {
    match spki.algorithm().parameters() {
        Some(Asn1Object::Oid(oid)) => oid.to_string(),
        _ => panic!("no named curve"),
    }
}

#[test]
fn an_ec_public_key_becomes_id_ec_public_key_with_its_curve_and_reads_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let spki = ec_spki(oper.as_ref(), "P-256");

    assert_eq!(
        spki.algorithm().algorithm().to_string(),
        "1.2.840.10045.2.1"
    );
    assert_eq!(curve_oid(&spki), "1.2.840.10045.3.1.7");
    let point = spki.subject_public_key().as_bytes();
    assert_eq!((point.len(), point[0]), (65, 0x04));

    let key = oper.spki().decode(&spki).unwrap();
    assert_eq!(oper.spki().encode(key.as_ref()).unwrap(), spki);
}

#[test]
fn curves_that_share_a_type_get_their_own_oids() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    for (curve, oid) in [
        ("secp112r1", "1.3.132.0.6"),
        ("secp112r2", "1.3.132.0.7"),
        ("brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7"),
        ("sect163k1", "1.3.132.0.1"),
        ("sect163r2", "1.3.132.0.15"),
    ] {
        let spki = ec_spki(oper.as_ref(), curve);
        assert_eq!(curve_oid(&spki), oid, "{curve}");
        let key = oper.spki().decode(&spki).unwrap();
        assert_eq!(oper.spki().encode(key.as_ref()).unwrap(), spki, "{curve}");
    }
}

#[test]
fn an_ec_spki_without_a_named_curve_or_of_an_unknown_one_is_refused() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let point = ec_spki(oper.as_ref(), "P-256")
        .subject_public_key()
        .as_bytes()
        .to_vec();

    let implicit = SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::with_null("1.2.840.10045.2.1".parse().unwrap()),
        Asn1BitString::from_bytes(&point),
    );
    let error = oper.spki().decode(&implicit).err().unwrap();
    assert!(matches!(error, AlgoAsn1Error::InvalidPublicKey));

    let unknown = SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::with_parameters(
            "1.2.840.10045.2.1".parse().unwrap(),
            Asn1Object::Oid("1.2.3.4".parse().unwrap()),
        ),
        Asn1BitString::from_bytes(&point),
    );
    let error = oper.spki().decode(&unknown).err().unwrap();
    assert!(matches!(error, AlgoAsn1Error::UnknownPublicKey));
}

#[test]
fn an_x448_public_key_becomes_id_x448_with_its_56_bytes_and_reads_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let mut key_gen = algo().key_pair_generator().get_by_name("X448").unwrap();
    let pair = key_gen.generate().unwrap();
    let original = pair
        .public()
        .as_any()
        .downcast_ref::<X448PublicKey>()
        .unwrap();

    let spki = oper.spki().encode(pair.public()).unwrap();
    assert_eq!(spki.algorithm().algorithm().to_string(), "1.3.101.111");
    assert!(spki.algorithm().parameters().is_none());
    assert_eq!(spki.subject_public_key().as_bytes(), original.u());

    let key = oper.spki().decode(&spki).unwrap();
    let key = key.as_any().downcast_ref::<X448PublicKey>().unwrap();
    assert_eq!(key.u(), original.u());
}

// The public key OpenSSL derives from its private key reads back, and matches the one this crate
// derives from the same private key
#[test]
fn the_x448_public_key_openssl_wrote_reads_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let der = include_bytes!("data/openssl_x448_spki.der");
    let (_, spki) = SubjectPublicKeyInfo::decode(der, &DecodingOptions::default()).unwrap();
    let key = oper.spki().decode(&spki).unwrap();
    assert_eq!(oper.spki().encode(key.as_ref()).unwrap(), spki);

    let (_, info) = PrivateKeyInfo::decode(
        include_bytes!("data/openssl_x448.der"),
        &DecodingOptions::default(),
    )
    .unwrap();
    let private = oper.private_key_info().decode(&info).unwrap();
    let private = private.as_any().downcast_ref::<X448PrivateKey>().unwrap();
    let derived = private.generate_public_key();
    let read = key.as_any().downcast_ref::<X448PublicKey>().unwrap();
    assert_eq!(derived.u(), read.u());
}
