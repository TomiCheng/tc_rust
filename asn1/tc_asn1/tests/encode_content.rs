use tc_asn1::*;

const RULES: [&EncodingOptions; 4] = [
    &EncodingOptions::new(EncodingType::Ber(LengthForm::Definite)),
    &EncodingOptions::new(EncodingType::Ber(LengthForm::Indefinite)),
    &EncodingOptions::new(EncodingType::Cer),
    &EncodingOptions::new(EncodingType::Der),
];

fn check<T: Encode + EncodeContent>(value: T) {
    let encoder: &dyn EncodeContent = &value;
    for rules in RULES {
        let wire = value.encode_to_vec(rules).unwrap();
        let parsed = Asn1Ref::parse(&wire, DecodingOptions::default()).unwrap();
        let expected = parsed.value();
        let len = encoder.content_len(rules);
        assert_eq!(
            len,
            expected.len(),
            "{} {rules:?}",
            core::any::type_name::<T>()
        );
        assert_eq!(encoder.encode_content_to_vec(rules).unwrap(), expected);

        let mut exact = vec![0xAA; len];
        assert_eq!(encoder.encode_content(rules, &mut exact), Ok(len));
        assert_eq!(exact, expected);
        let mut oversized = vec![0xAA; len + 3];
        assert_eq!(encoder.encode_content(rules, &mut oversized), Ok(len));
        assert_eq!(&oversized[..len], expected);
        assert_eq!(&oversized[len..], &[0xAA; 3]);
        if len > 0 {
            let mut short = vec![0xAA; len - 1];
            assert_eq!(
                encoder.encode_content(rules, &mut short),
                Err(Asn1Error::BufferTooSmall)
            );
            assert!(short.iter().all(|byte| *byte == 0xAA));
        }
    }
}

fn check_decoded<T>(contents: &[u8])
where
    T: for<'a> DecodeContent<'a> + Encode + EncodeContent,
{
    check(T::decode_content(contents, DecodingOptions::default()).unwrap());
}

#[test]
fn every_universal_value_encodes_contents_through_the_public_trait() {
    check_decoded::<Asn1BitString>(&[3, 0xF8]);
    check_decoded::<Asn1Boolean>(&[0xFF]);
    check_decoded::<Asn1Enumerated>(&[3]);
    check_decoded::<Asn1Integer>(&[0x80]);
    check_decoded::<Asn1Null>(&[]);
    check_decoded::<Asn1Oid>(&[0x2A, 3]);
    check_decoded::<Asn1RelativeOid>(&[3, 4]);
    check_decoded::<Asn1OidIri>(b"/ISO/Registration_Authority");
    check_decoded::<Asn1RelativeOidIri>(b"Registration_Authority");
    check_decoded::<Asn1Real>(&[0x80, 0, 1]);
    check_decoded::<Asn1UtcTime>(b"240101000000Z");
    check_decoded::<Asn1GeneralizedTime>(b"20240101000000Z");
    check_decoded::<Asn1Time>(b"R/P1W");
    check_decoded::<Asn1Date>(b"20240101");
    check_decoded::<Asn1TimeOfDay>(b"123456");
    check_decoded::<Asn1DateTime>(b"20240101123456");
    check_decoded::<Asn1Duration>(b"1D");

    check_decoded::<Asn1BmpString>(&[0x53, 0xF0]);
    check_decoded::<Asn1UniversalString>(&[0, 0, 0x53, 0xF0]);
    check_decoded::<Asn1Utf8String>("台".as_bytes());
    check_decoded::<Asn1Ia5String>(b"text");
    check_decoded::<Asn1NumericString>(b"12 3");
    check_decoded::<Asn1PrintableString>(b"text");
    check_decoded::<Asn1VisibleString>(b"text");
    check_decoded::<Asn1OctetString>(&[0x00, 0xFF]);
    check_decoded::<Asn1GeneralString>(&[0xFF]);
    check_decoded::<Asn1GraphicString>(&[0xFF]);
    check_decoded::<Asn1ObjectDescriptor>(&[0xFF]);
    check_decoded::<Asn1TeletexString>(&[0xFF]);
    check_decoded::<Asn1VideotexString>(&[0xFF]);
    check(Asn1SequenceOf::from(vec![
        Asn1Boolean::from(true),
        Asn1Boolean::from(false),
    ]));
    check(Asn1SetOf::from(vec![
        Asn1Boolean::from(true),
        Asn1Boolean::from(false),
    ]));
    check(Asn1SequenceOf::<Asn1Null>::new());
    check(Asn1SetOf::<Asn1Null>::new());
    check_decoded::<Asn1Real>(&[]);
}

#[test]
fn cer_strings_cover_empty_values_thresholds_and_complete_final_segments() {
    for len in [0, 999, 1000, 1001, 2000, 2001] {
        let contents = vec![b'1'; len];
        check_decoded::<Asn1OctetString>(&contents);
        check_decoded::<Asn1Utf8String>(&contents);
        check_decoded::<Asn1Ia5String>(&contents);
        check_decoded::<Asn1NumericString>(&contents);
        check_decoded::<Asn1PrintableString>(&contents);
        check_decoded::<Asn1VisibleString>(&contents);
        check_decoded::<Asn1GeneralString>(&contents);
        check_decoded::<Asn1GraphicString>(&contents);
        check_decoded::<Asn1ObjectDescriptor>(&contents);
        check_decoded::<Asn1TeletexString>(&contents);
        check_decoded::<Asn1VideotexString>(&contents);
        check_decoded::<Asn1BmpString>(&[0x53, 0xF0].repeat(len / 2));
        check_decoded::<Asn1UniversalString>(&[0, 0, 0x53, 0xF0].repeat(len / 4));
    }
    check_decoded::<Asn1BmpString>(&[0x53, 0xF0].repeat(501));
    check_decoded::<Asn1UniversalString>(&[0, 0, 0x53, 0xF0].repeat(251));
    check_decoded::<Asn1Utf8String>(("a".repeat(999) + "€").as_bytes());

    let mut expected = vec![4, 0x82, 3, 0xE8];
    expected.extend_from_slice(&[0xAA; 1000]);
    expected.extend_from_slice(&[4, 1, 0xAA]);
    assert_eq!(
        Asn1OctetString::new(&[0xAA; 1001])
            .encode_content_to_vec(&EncodingOptions::new(EncodingType::Cer))
            .unwrap(),
        expected
    );
}

#[test]
fn long_iris_keep_primitive_contents() {
    let label = "a".repeat(1001);
    check(Asn1OidIri::new(&format!("/ISO/{label}")).unwrap());
    check(Asn1RelativeOidIri::new(&label).unwrap());
}

#[test]
fn constructed_contents_preserve_child_headers_end_markers_and_set_ordering() {
    let oid = Asn1Oid::from_arcs(&[2, 1, 1]).unwrap();
    for identification in [
        PdvIdentification::Fixed,
        PdvIdentification::Syntax(oid.clone()),
        PdvIdentification::TransferSyntax(oid.clone()),
        PdvIdentification::PresentationContextId(5_u8.into()),
        PdvIdentification::Syntaxes {
            abstract_syntax: oid.clone(),
            transfer_syntax: oid.clone(),
        },
        PdvIdentification::ContextNegotiation {
            presentation_context_id: 5_u8.into(),
            transfer_syntax: oid.clone(),
        },
    ] {
        check(identification.clone());
        for len in [0, 1000, 1001] {
            check(Asn1EmbeddedPdv::new(
                identification.clone(),
                vec![0xAA; len],
            ));
            check(Asn1CharacterString::new(
                identification.clone(),
                vec![0xAA; len],
            ));
        }
    }
    for encoding in [
        ExternalEncoding::SingleAsn1Type(Box::new(Asn1Object::Sequence(vec![
            Asn1Boolean::from(true).into(),
        ]))),
        ExternalEncoding::OctetAligned(Asn1OctetString::new(&[0xAA; 1001])),
        ExternalEncoding::Arbitrary(Asn1BitString::from_bits(&[0xF8; 1000], 7997)),
    ] {
        check(Asn1External::new(None, None, None, encoding.clone()));
        check(Asn1External::new(
            Some(oid.clone()),
            Some(5_u8.into()),
            Some(Asn1ObjectDescriptor::new(&[b'a'; 1001])),
            encoding,
        ));
    }
    check(Asn1SequenceOf::from(vec![Asn1SetOf::from(vec![
        Asn1OctetString::new(&[0xFF; 1001]),
        Asn1OctetString::new(&[0x00; 1001]),
    ])]));
    let set = Asn1SetOf::from(vec![Asn1Boolean::from(true), Asn1Boolean::from(false)]);
    for rules in RULES {
        let expected = if rules.is_canonical() {
            [1, 1, 0, 1, 1, 0xFF]
        } else {
            [1, 1, 0xFF, 1, 1, 0]
        };
        assert_eq!(set.encode_content_to_vec(rules).unwrap(), expected);
    }
}

#[test]
fn collections_propagate_child_encoding_errors_to_the_vec_helper() {
    struct Failing;
    impl tc_asn1::EncodeContent for Failing {
        fn content_len(&self, _: &EncodingOptions) -> usize {
            1
        }

        fn encode_content(&self, _: &EncodingOptions, _: &mut [u8]) -> Result<usize, Asn1Error> {
            Err(Asn1Error::MalformedValue)
        }
    }

    impl tc_asn1::EncodeTagged for Failing {}

    impl Encode for Failing {
        fn encoded_len(&self, rules: &tc_asn1::EncodingOptions) -> usize {
            tc_asn1::EncodeTagged::encoded_len_tagged(self, tag::INTEGER, rules)
        }

        fn encode(
            &self,
            rules: &tc_asn1::EncodingOptions,
            out: &mut [u8],
        ) -> Result<usize, tc_asn1::Asn1Error> {
            tc_asn1::EncodeTagged::encode_tagged(self, tag::INTEGER, rules, out)
        }
    }
    for rules in RULES {
        assert_eq!(
            Asn1SequenceOf::from(vec![Failing]).encode_content_to_vec(rules),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1SetOf::from(vec![Failing]).encode_content_to_vec(rules),
            Err(Asn1Error::MalformedValue)
        );
    }
}
