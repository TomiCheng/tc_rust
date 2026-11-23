use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
use tc_asn1::{
    Asn1Integer, Asn1Null, Asn1Object, Asn1OctetString, Decode, DecodingOptions, Encode,
    EncodingOptions,
};
use tc_asn1_cmp::{PbmParameter, crmf::CrmfId};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_crmf::{CrmfError, PkMacBuilder};

fn parameters(count: impl Into<Asn1Integer>) -> PbmParameter {
    PbmParameter::new(
        Asn1OctetString::new(b"12345678"),
        AlgorithmIdentifier::new("1.3.14.3.2.26".parse().unwrap()),
        count.into(),
        AlgorithmIdentifier::with_parameters("1.3.6.1.5.5.8.1.2".parse().unwrap(), Asn1Null),
    )
}

fn algorithm(parameters: &PbmParameter) -> AlgorithmIdentifier {
    let encoded = parameters.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (_, value) = Asn1Object::decode_der(&encoded, &DecodingOptions::default()).unwrap();
    AlgorithmIdentifier::with_parameters(CrmfId::PASSWORD_BASED_MAC.oid(), value)
}

#[test]
fn incoming_parameters_cannot_exceed_the_default_or_configured_iteration_ceiling() {
    let algo = DefaultAlgoBuilder::default().build();
    let make = || PkMacBuilder::new(algo.digest(), algo.mac());
    assert!(matches!(
        make().with_parameters(parameters(i32::MAX)),
        Err(CrmfError::IterationCountExceedsLimit {
            count: i32::MAX,
            max: 1_000_000
        })
    ));
    assert!(make().with_parameters(parameters(1000)).is_ok());

    let limited = make().with_max_iterations(100);
    assert!(matches!(
        limited.get(&algorithm(&parameters(101)), "fred"),
        Err(CrmfError::IterationCountExceedsLimit {
            count: 101,
            max: 100
        })
    ));
    assert!(limited.get(&algorithm(&parameters(100)), "fred").is_ok());

    let configured = make()
        .with_parameters(parameters(101))
        .unwrap()
        .with_max_iterations(100);
    assert!(matches!(
        configured.build("fred"),
        Err(CrmfError::IterationCountExceedsLimit {
            count: 101,
            max: 100
        })
    ));
}

#[test]
fn incoming_parameters_reject_negative_and_zero_iteration_counts() {
    let algo = DefaultAlgoBuilder::default().build();
    for count in [-1, 0] {
        assert!(matches!(
            PkMacBuilder::new(algo.digest(), algo.mac()).with_parameters(parameters(count)),
            Err(CrmfError::IterationCountBelowOne)
        ));
    }
}

#[test]
fn incoming_parameters_reject_counts_outside_the_signed_thirty_two_bit_range() {
    let algo = DefaultAlgoBuilder::default().build();
    for count in [i64::from(i32::MAX) + 1, i64::from(i32::MIN) - 1] {
        assert!(matches!(
            PkMacBuilder::new(algo.digest(), algo.mac()).with_parameters(parameters(count)),
            Err(CrmfError::IterationCountOutsideInt32)
        ));
    }
}

#[test]
fn the_password_based_mac_matches_an_independent_sha_one_known_answer() {
    let algo = DefaultAlgoBuilder::default().build();
    let make = || PkMacBuilder::new(algo.digest(), algo.mac());
    assert!(make().with_salt_length(7).is_err());
    assert!(make().with_iteration_count(99).is_err());
    let builder = make().with_parameters(parameters(100)).unwrap();
    let mac = builder.build("fred").unwrap();
    let expected = [
        0xc0, 0xf1, 0xb8, 0x2a, 0x7f, 0xf5, 0x9b, 0xf2, 0x81, 0xa5, 0xea, 0xae, 0x71, 0x19, 0x58,
        0xe5, 0x51, 0xd0, 0x32, 0xc6,
    ];
    assert_eq!(mac.calculate(b"message").unwrap(), expected);
    assert!(
        make()
            .get(mac.algorithm(), "fred")
            .unwrap()
            .verify(b"message", &expected)
            .unwrap()
    );
    assert!(
        !make()
            .get(mac.algorithm(), "wrong")
            .unwrap()
            .verify(b"message", &expected)
            .unwrap()
    );

    let fresh = make().build("fred").unwrap();
    let encoded = fresh
        .algorithm()
        .parameters()
        .unwrap()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    let (_, actual) = PbmParameter::decode_der(&encoded, &DecodingOptions::default()).unwrap();
    assert_eq!(actual.iteration_count(), &1000.into());
    assert_eq!(actual.salt().as_bytes().len(), 20);
    assert_eq!(actual.owf(), parameters(100).owf());
    assert_eq!(actual.mac(), parameters(100).mac());
    assert_ne!(fresh.algorithm(), make().build("fred").unwrap().algorithm());
}
