use std::any::Any;

use tc_algo::Params;
use tc_algo::generate::KeyPair;
use tc_algo::params::{
    generate::DsaKeyGenParams, generate::EcKeyGenParams, generate::RsaKeyGenParams,
    key::DsaPrivateKey, key::Ed25519PrivateKey, key::RsaKey, key::RsaKeyParams,
    key::X448PrivateKey, key::X25519PrivateKey,
};
use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_algo_asn1::{AlgoAsn1, AlgoAsn1Builder, AlgoAsn1Error, DefaultAlgoAsn1Builder};
use tc_asn1::{Asn1Object, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;

fn algo() -> Box<dyn Algo> {
    DefaultAlgoBuilder::default().build()
}

fn pair(name: &str, params: Option<&dyn Params>) -> KeyPair {
    let mut key_gen = algo().key_pair_generator().get_by_name(name).unwrap();
    if let Some(params) = params {
        key_gen.init(params).unwrap();
    }
    key_gen.generate().unwrap()
}

// The key read back writes the same PrivateKeyInfo
fn round_trip(oper: &dyn AlgoAsn1, key: &dyn Params) -> PrivateKeyInfo {
    let info = oper.pkcs8().encode(key).unwrap();
    let back = oper.pkcs8().decode(&info).unwrap();
    assert_eq!(oper.pkcs8().encode(back.as_ref()).unwrap(), info);
    info
}

#[test]
fn an_rsa_private_key_becomes_rsa_encryption_and_reads_back_with_its_crt_values() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    // Small, since generating the primes is slow
    let pair = pair("RSA", Some(&RsaKeyGenParams::new(1024)));

    let info = round_trip(oper.as_ref(), pair.private());
    assert_eq!(
        info.algorithm().algorithm().to_string(),
        "1.2.840.113549.1.1.1"
    );
    assert_eq!(info.version(), 0);

    let key = oper.pkcs8().decode(&info).unwrap();
    let key = key.as_any().downcast_ref::<RsaKey>().unwrap();
    assert!(matches!(key, RsaKey::Crt(_)));
    let original = pair.private().as_any().downcast_ref::<RsaKey>().unwrap();
    assert_eq!(key.modulus(), original.modulus());
}

#[test]
fn a_public_key_is_refused() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = pair("RSA", Some(&RsaKeyGenParams::new(1024)));

    let error = oper.pkcs8().encode(pair.public()).unwrap_err();
    assert!(matches!(error, AlgoAsn1Error::NotPrivateKey));
}

#[test]
fn an_x25519_private_key_carries_its_public_key_and_reads_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = pair("X25519", None);

    let info = round_trip(oper.as_ref(), pair.private());
    assert_eq!(info.algorithm().algorithm().to_string(), "1.3.101.110");
    assert!(info.algorithm().parameters().is_none());
    assert_eq!(info.version(), 1);
    let spki = oper.spki().encode(pair.public()).unwrap();
    assert_eq!(
        info.public_key().unwrap().as_bytes(),
        spki.subject_public_key().as_bytes()
    );
}

#[test]
fn an_x25519_key_is_also_read_bare_and_under_cryptlibs_oid() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let k = [7; 32];
    for (oid, octets) in [
        ("1.3.101.110", k.to_vec()),
        (
            "1.3.6.1.4.1.3029.1.5.1",
            Asn1OctetString::new(&k)
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
        ),
    ] {
        let info = PrivateKeyInfo::new(
            AlgorithmIdentifier::new(oid.parse().unwrap()),
            Asn1OctetString::new(&octets),
        );
        let key = oper.pkcs8().decode(&info).unwrap();
        let key = key.as_any().downcast_ref::<X25519PrivateKey>().unwrap();
        assert_eq!(key.k(), &k, "{oid}");
    }
}

#[test]
fn an_ec_private_key_carries_its_curve_and_public_key_and_reads_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = pair("EC", Some(&EcKeyGenParams::new("P-256") as &dyn Params));

    let info = round_trip(oper.as_ref(), pair.private());
    assert_eq!(
        info.algorithm().algorithm().to_string(),
        "1.2.840.10045.2.1"
    );
    assert!(matches!(
        info.algorithm().parameters(),
        Some(Asn1Object::Oid(curve)) if curve.to_string() == "1.2.840.10045.3.1.7"
    ));
}

#[test]
fn an_ec_key_without_a_named_curve_is_invalid() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = pair("EC", Some(&EcKeyGenParams::new("P-256") as &dyn Params));
    let info = oper.pkcs8().encode(pair.private()).unwrap();

    let implicit = PrivateKeyInfo::new(
        AlgorithmIdentifier::with_null("1.2.840.10045.2.1".parse().unwrap()),
        info.private_key().clone(),
    );
    let error = oper.pkcs8().decode(&implicit).err().unwrap();
    assert!(matches!(error, AlgoAsn1Error::InvalidPrivateKey));
}

struct OtherKey;

impl Params for OtherKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn a_key_or_an_algorithm_no_row_knows_is_unknown() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let error = oper.pkcs8().encode(&OtherKey).unwrap_err();
    assert!(matches!(error, AlgoAsn1Error::UnknownPrivateKey));

    let info = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
        Asn1OctetString::new(&[0]),
    );
    let error = oper.pkcs8().decode(&info).err().unwrap();
    assert!(matches!(error, AlgoAsn1Error::UnknownPrivateKey));
}

#[test]
fn every_cfrg_private_key_carries_its_public_key_under_its_rfc_8410_oid_and_reads_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    for (name, oid) in [
        ("X25519", "1.3.101.110"),
        ("X448", "1.3.101.111"),
        ("Ed25519", "1.3.101.112"),
        ("Ed448", "1.3.101.113"),
    ] {
        let pair = pair(name, None);
        let info = round_trip(oper.as_ref(), pair.private());
        assert_eq!(info.algorithm().algorithm().to_string(), oid, "{name}");
        assert!(info.algorithm().parameters().is_none(), "{name}");
        assert_eq!(info.version(), 1, "{name}");
        assert!(info.public_key().is_some(), "{name}");
    }
}

#[test]
fn an_ed25519_key_is_read_under_gnus_oid_but_not_bare() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let k = [9; 32];
    let wrapped = Asn1OctetString::new(&k)
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    let gnu = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.3.6.1.4.1.11591.15.1".parse().unwrap()),
        Asn1OctetString::new(&wrapped),
    );
    let key = oper.pkcs8().decode(&gnu).unwrap();
    let key = key.as_any().downcast_ref::<Ed25519PrivateKey>().unwrap();
    assert_eq!(key.k(), &k);

    // Bouncy Castle takes a bare key only for X25519 and X448
    let bare = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.3.101.112".parse().unwrap()),
        Asn1OctetString::new(&k),
    );
    assert!(oper.pkcs8().decode(&bare).is_err());
}

#[test]
fn an_x448_key_is_also_read_bare() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let k = [5; 56];
    let info = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.3.101.111".parse().unwrap()),
        Asn1OctetString::new(&k),
    );
    let key = oper.pkcs8().decode(&info).unwrap();
    let key = key.as_any().downcast_ref::<X448PrivateKey>().unwrap();
    assert_eq!(key.k(), &k);
}

#[test]
fn a_dsa_private_key_carries_its_domain_and_reads_back_with_the_same_x() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    let pair = pair("DSA", Some(&DsaKeyGenParams::new(1024, 160)));
    let info = round_trip(oper.as_ref(), pair.private());
    assert_eq!(
        info.algorithm().algorithm().to_string(),
        "1.2.840.10040.4.1"
    );
    assert!(info.algorithm().parameters().is_some());
    assert_eq!(info.version(), 0);

    let original = pair
        .private()
        .as_any()
        .downcast_ref::<DsaPrivateKey>()
        .unwrap();
    let back = oper.pkcs8().decode(&info).unwrap();
    let back = back.as_any().downcast_ref::<DsaPrivateKey>().unwrap();
    assert_eq!(back.x(), original.x());
    assert_eq!(back.params(), original.params());

    // Without the domain the key cannot be used, so it is refused
    let bare = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.2.840.10040.4.1".parse().unwrap()),
        Asn1OctetString::new(info.private_key().as_bytes()),
    );
    let error = oper.pkcs8().decode(&bare).err().unwrap();
    assert!(matches!(error, AlgoAsn1Error::InvalidPrivateKey));
}

// OpenSSL writes version 1 without the public key; each still reads and writes back the key
#[test]
fn private_keys_openssl_wrote_read_back() {
    let oper = DefaultAlgoAsn1Builder::default().build();
    for (name, der) in [
        ("Ed25519", &include_bytes!("data/openssl_ed25519.der")[..]),
        ("Ed448", &include_bytes!("data/openssl_ed448.der")[..]),
        ("X25519", &include_bytes!("data/openssl_x25519.der")[..]),
        ("X448", &include_bytes!("data/openssl_x448.der")[..]),
        ("DSA", &include_bytes!("data/openssl_dsa.der")[..]),
    ] {
        let (_, info) = PrivateKeyInfo::decode(der, &DecodingOptions::default()).unwrap();
        let key = oper.pkcs8().decode(&info).unwrap();
        let written = oper.pkcs8().encode(key.as_ref()).unwrap();
        assert_eq!(written.private_key(), info.private_key(), "{name}");
        assert_eq!(written.algorithm(), info.algorithm(), "{name}");
    }
}
