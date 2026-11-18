use std::any::Any;

use tc_algo::Params;
use tc_algo::generate::KeyPair;
use tc_asn1::{Asn1Object, Asn1OctetString, Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsError, PkcsOperator, PkcsOperatorBuilder};
use tc_x509::operator::params::{
    EcKeyGenParams, RsaKey, RsaKeyGenParams, RsaKeyParams, X25519PrivateKey,
};

fn pair(oper: &dyn PkcsOperator, name: &str, params: Option<&dyn Params>) -> KeyPair {
    let mut key_gen = oper.x509().key_pair_generator().get_by_name(name).unwrap();
    if let Some(params) = params {
        key_gen.init(params).unwrap();
    }
    key_gen.generate().unwrap()
}

// The key read back writes the same PrivateKeyInfo
fn round_trip(oper: &dyn PkcsOperator, key: &dyn Params) -> PrivateKeyInfo {
    let info = oper.private_key_info().encode(key).unwrap();
    let back = oper.private_key_info().decode(&info).unwrap();
    assert_eq!(oper.private_key_info().encode(back.as_ref()).unwrap(), info);
    info
}

#[test]
fn an_rsa_private_key_becomes_rsa_encryption_and_reads_back_with_its_crt_values() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    // Small, since generating the primes is slow
    let pair = pair(oper.as_ref(), "RSA", Some(&RsaKeyGenParams::new(1024)));

    let info = round_trip(oper.as_ref(), pair.private());
    assert_eq!(
        info.algorithm().algorithm().to_string(),
        "1.2.840.113549.1.1.1"
    );
    assert_eq!(info.version(), 0);

    let key = oper.private_key_info().decode(&info).unwrap();
    let key = key.as_any().downcast_ref::<RsaKey>().unwrap();
    assert!(matches!(key, RsaKey::Crt(_)));
    let original = pair.private().as_any().downcast_ref::<RsaKey>().unwrap();
    assert_eq!(key.modulus(), original.modulus());
}

#[test]
fn a_public_key_is_refused() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let pair = pair(oper.as_ref(), "RSA", Some(&RsaKeyGenParams::new(1024)));

    let error = oper.private_key_info().encode(pair.public()).unwrap_err();
    assert!(matches!(error, PkcsError::NotPrivateKey));
}

#[test]
fn an_x25519_private_key_carries_its_public_key_and_reads_back() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let pair = pair(oper.as_ref(), "X25519", None);

    let info = round_trip(oper.as_ref(), pair.private());
    assert_eq!(info.algorithm().algorithm().to_string(), "1.3.101.110");
    assert!(info.algorithm().parameters().is_none());
    assert_eq!(info.version(), 1);
    let spki = oper.x509().spki().encode(pair.public()).unwrap();
    assert_eq!(
        info.public_key().unwrap().as_bytes(),
        spki.subject_public_key().as_bytes()
    );
}

#[test]
fn an_x25519_key_is_also_read_bare_and_under_cryptlibs_oid() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
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
        let key = oper.private_key_info().decode(&info).unwrap();
        let key = key.as_any().downcast_ref::<X25519PrivateKey>().unwrap();
        assert_eq!(key.k(), &k, "{oid}");
    }
}

#[test]
fn an_ec_private_key_carries_its_curve_and_public_key_and_reads_back() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let pair = pair(
        oper.as_ref(),
        "EC",
        Some(&EcKeyGenParams::new("P-256") as &dyn Params),
    );

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
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let pair = pair(
        oper.as_ref(),
        "EC",
        Some(&EcKeyGenParams::new("P-256") as &dyn Params),
    );
    let info = oper.private_key_info().encode(pair.private()).unwrap();

    let implicit = PrivateKeyInfo::new(
        AlgorithmIdentifier::with_null("1.2.840.10045.2.1".parse().unwrap()),
        info.private_key().clone(),
    );
    let error = oper.private_key_info().decode(&implicit).err().unwrap();
    assert!(matches!(error, PkcsError::InvalidPrivateKey));
}

struct OtherKey;

impl Params for OtherKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn a_key_or_an_algorithm_no_row_knows_is_unknown() {
    let oper = DefaultPkcsOperatorBuilder::default().build();
    let error = oper.private_key_info().encode(&OtherKey).unwrap_err();
    assert!(matches!(error, PkcsError::UnknownPrivateKey));

    let info = PrivateKeyInfo::new(
        AlgorithmIdentifier::new("1.2.3".parse().unwrap()),
        Asn1OctetString::new(&[0]),
    );
    let error = oper.private_key_info().decode(&info).err().unwrap();
    assert!(matches!(error, PkcsError::UnknownPrivateKey));
}
