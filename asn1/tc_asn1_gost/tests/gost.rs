use std::fmt::Debug;

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1_gost::{
    CryptoProId, EcGost3410ParamSetParameters, Gost3410ParamSetParameters,
    Gost3410PublicKeyAlgParameters, Gost28147Parameters, GostR3410x2001PublicKeyParameters,
    GostR3410x2012PublicKeyParameters, RosstandartId,
};

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    assert_eq!(
        T::decode_der(&der, &DecodingOptions::default()).unwrap().1,
        *value
    );
    der
}

fn sequence(oids: &[Asn1Oid]) -> Vec<u8> {
    let mut content = Vec::new();
    for oid in oids {
        content.extend(oid.encode_to_vec(&EncodingOptions::DER).unwrap());
    }
    let mut encoding = vec![0x30, content.len() as u8];
    encoding.extend(content);
    encoding
}

fn curve_a() -> Asn1Oid {
    CryptoProId::GOST_R3410_X2001_CRYPTO_PRO_A.oid()
}

fn digest_94() -> Asn1Oid {
    CryptoProId::GOST_R3411_X94_CRYPTO_PRO_PARAM_SET.oid()
}

fn encryption_a() -> Asn1Oid {
    CryptoProId::GOST28147_89_CRYPTO_PRO_A_PARAM_SET.oid()
}

fn encryption_b() -> Asn1Oid {
    CryptoProId::GOST28147_89_CRYPTO_PRO_B_PARAM_SET.oid()
}

#[test]
fn bc_2001_parameters_default_to_the_cryptopro_a_encryption_set() {
    let encoding = sequence(&[curve_a(), digest_94()]);
    let options = DecodingOptions::default();
    let parameters = GostR3410x2001PublicKeyParameters::decode_der(&encoding, &options)
        .unwrap()
        .1;
    assert_eq!(parameters.encryption_param_set(), &encryption_a());
    assert_eq!(round_trip(&parameters), encoding);
    assert_eq!(
        parameters,
        GostR3410x2001PublicKeyParameters::new(curve_a(), digest_94())
            .with_encryption_param_set(encryption_a())
    );
}

#[test]
fn bc_2001_parameters_omit_a_written_default_and_reject_it_under_der() {
    let written = sequence(&[curve_a(), digest_94(), encryption_a()]);
    let options = DecodingOptions::default();
    assert_eq!(
        GostR3410x2001PublicKeyParameters::decode_der(&written, &options),
        Err(Asn1Error::NotDer)
    );
    let parameters = GostR3410x2001PublicKeyParameters::decode(&written, &options)
        .unwrap()
        .1;
    assert_eq!(round_trip(&parameters), sequence(&[curve_a(), digest_94()]));
}

#[test]
fn bc_2001_parameters_keep_another_encryption_set() {
    let encoding = sequence(&[curve_a(), digest_94(), encryption_b()]);
    let parameters =
        GostR3410x2001PublicKeyParameters::decode_der(&encoding, &DecodingOptions::default())
            .unwrap()
            .1;
    assert_eq!(parameters.encryption_param_set(), &encryption_b());
    assert_eq!(round_trip(&parameters), encoding);
}

#[test]
fn bc_2001_parameters_require_a_digest_set_of_identifiers() {
    let options = DecodingOptions::default();
    assert!(
        GostR3410x2001PublicKeyParameters::decode_der(&sequence(&[curve_a()]), &options).is_err()
    );
    let mut with_null = sequence(&[curve_a()]);
    with_null.extend([5, 0]);
    with_null[1] += 2;
    assert!(GostR3410x2001PublicKeyParameters::decode_der(&with_null, &options).is_err());
}

#[test]
fn the_general_form_writes_encryption_only_after_a_digest() {
    let curve_only = Gost3410PublicKeyAlgParameters::new(curve_a());
    assert_eq!(round_trip(&curve_only), sequence(&[curve_a()]));
    let full = curve_only
        .clone()
        .with_digest_param_set(digest_94())
        .with_encryption_param_set(encryption_b());
    assert_eq!(
        round_trip(&full),
        sequence(&[curve_a(), digest_94(), encryption_b()])
    );
    let orphan = curve_only.with_encryption_param_set(encryption_b());
    assert_eq!(
        orphan.encode_to_vec(&EncodingOptions::DER).unwrap(),
        sequence(&[curve_a()])
    );
}

#[test]
fn the_2012_form_has_an_optional_digest() {
    let curve = RosstandartId::GOST_3410_12_256_PARAM_SET_A.oid();
    let parameters = GostR3410x2012PublicKeyParameters::new(curve.clone());
    assert_eq!(
        round_trip(&parameters),
        sequence(std::slice::from_ref(&curve))
    );
    let digest = RosstandartId::GOST_3411_12_256.oid();
    round_trip(&parameters.with_digest_param_set(digest));
}

#[test]
fn group_curve_and_cipher_parameters_round_trip() {
    round_trip(&EcGost3410ParamSetParameters::new(
        7.into(),
        0x5fbf.into(),
        0x8000_0431u32.into(),
        0x8000_0001u32.into(),
        2.into(),
        0x08e2.into(),
    ));
    round_trip(&Gost3410ParamSetParameters::new(
        512.into(),
        23.into(),
        11.into(),
        2.into(),
    ));
    round_trip(&Gost28147Parameters::new(
        Asn1OctetString::new(&[1; 8]),
        RosstandartId::GOST_28147_PARAM_Z.oid(),
    ));
}

#[test]
fn identifier_tables_sit_under_their_arcs() {
    assert_eq!(encryption_a().to_string(), "1.2.643.2.2.31.1");
    assert_eq!(
        RosstandartId::from_oid(&RosstandartId::GOST_3411_12_512.oid()),
        Some(RosstandartId::GOST_3411_12_512)
    );
}
