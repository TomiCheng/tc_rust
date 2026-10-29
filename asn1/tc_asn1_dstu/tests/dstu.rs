use std::fmt::Debug;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1_dstu::{
    Dstu4145BinaryField, Dstu4145Curve, Dstu4145EcBinary, Dstu4145Exponents, Dstu4145Params,
    Dstu4145Pentanomial, UaId,
};

fn round_trip<T: Decode + Encode + PartialEq + Debug>(value: &T) -> Vec<u8> {
    let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
    assert_eq!(
        T::decode_der(&der, &DecodingOptions::default()).unwrap().1,
        *value
    );
    der
}

/// The shape of DSTU 4145 curve M163: `x^163 + x^7 + x^6 + x^3 + 1`.
fn m163() -> Dstu4145EcBinary {
    let field = Dstu4145BinaryField::new(
        163.into(),
        Dstu4145Exponents::Pentanomial(Dstu4145Pentanomial::new(7.into(), 6.into(), 3.into())),
    );
    Dstu4145EcBinary::new(
        field,
        1.into(),
        Asn1OctetString::new(&[0x5f; 21]),
        Asn1Integer::from_unsigned_bytes(&[0x04; 21]),
        Asn1OctetString::new(&[0x2e; 22]),
    )
}

#[test]
fn trinomial_and_pentanomial_fields_round_trip() {
    let trinomial = Dstu4145BinaryField::new(167.into(), Dstu4145Exponents::Trinomial(6.into()));
    assert_eq!(round_trip(&trinomial), [0x30, 7, 2, 2, 0, 167, 2, 1, 6]);
    round_trip(m163().f());
}

#[test]
fn the_default_version_is_omitted_and_rejected_when_written_under_der() {
    let curve = m163();
    let omitted = round_trip(&curve);
    assert_eq!(curve.version(), 0.into());
    assert_eq!(curve.clone().with_version(0.into()), curve);

    let mut written = vec![0xa0, 3, 2, 1, 0];
    written.extend(&omitted[2..]);
    let mut encoding = vec![0x30, written.len() as u8];
    encoding.extend(written);
    let options = DecodingOptions::default();
    assert_eq!(
        Dstu4145EcBinary::decode_der(&encoding, &options),
        Err(Asn1Error::NotDer)
    );
    assert_eq!(
        Dstu4145EcBinary::decode(&encoding, &options).unwrap().1,
        curve
    );

    let version_1 = round_trip(&curve.with_version(1.into()));
    assert_eq!(version_1[2..7], [0xa0, 3, 2, 1, 1]);
}

#[test]
fn params_name_a_curve_or_give_it_explicitly() {
    let named = Dstu4145Params::new(Dstu4145Curve::NamedCurve(
        "1.2.804.2.1.1.1.1.3.1.1.2.0".parse().unwrap(),
    ));
    assert_eq!(round_trip(&named)[2], 0x06);
    assert!(named.dke().is_none());
    let explicit = Dstu4145Params::new(Dstu4145Curve::EcBinary(m163()));
    assert_eq!(round_trip(&explicit)[2], 0x30);
}

#[test]
fn a_written_dke_is_kept_and_must_be_64_octets() {
    let default = Asn1OctetString::new(&Dstu4145Params::DEFAULT_DKE);
    let params = Dstu4145Params::new(Dstu4145Curve::NamedCurve(UaId::DSTU4145_BE.oid()))
        .with_dke(default.clone())
        .unwrap();
    assert!(round_trip(&params).ends_with(&Dstu4145Params::DEFAULT_DKE));
    assert_eq!(params.dke(), Some(&default));

    let short = Dstu4145Params::new(Dstu4145Curve::NamedCurve(UaId::DSTU4145_BE.oid()))
        .with_dke(Asn1OctetString::new(&[0; 32]));
    assert_eq!(short, Err(Asn1Error::MalformedValue));
}

#[test]
fn ua_identifiers_cover_kupyna_and_kalyna() {
    assert_eq!(
        UaId::DSTU7564_DIGEST_256.dotted(),
        "1.2.804.2.1.1.1.1.2.2.1"
    );
    assert_eq!(UaId::DSTU7624_KW_512.dotted(), "1.2.804.2.1.1.1.1.1.3.10.3");
    assert_eq!(
        UaId::from_oid(&UaId::DSTU4145_LE.oid()),
        Some(UaId::DSTU4145_LE)
    );
}
