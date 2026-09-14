use tc_asn1::*;

#[test]
fn custom_identifiers_round_trip_after_the_schema_selects_the_type() {
    let value = Asn1Integer::from(42_u8);
    for tag in [&[0x80][..], &[0x5f, 0x81, 0], &[0xdf, 0x81, 0]] {
        let wire = Implicit::new(tag, &value)
            .encode_to_vec(&EncodingOptions::new(EncodingType::Der))
            .unwrap();
        let options = DecodingOptions::default();
        let (used, decoded) =
            Asn1Integer::decode_inner(&wire, &mut DecodingContext::new(&options)).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(decoded, value);
        let element = Asn1Ref::parse(&wire, &mut DecodingContext::new(&options)).unwrap();
        assert_eq!(element.tag(), tag);
        assert_eq!(
            element
                .decode_as::<Asn1Integer>(&mut DecodingContext::new(&options))
                .unwrap(),
            value
        );
        let mut context = DecodingContext::new(&options);
        let mut fields = Fields::new(&wire, &mut context).unwrap();
        assert_eq!(fields.required::<Asn1Integer>(tag).unwrap(), value);
        fields.finish().unwrap();
        assert_eq!(
            Fields::new(&wire, &mut DecodingContext::new(&options))
                .unwrap()
                .required::<Asn1Integer>(tag::INTEGER),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}

#[test]
fn the_first_tlv_is_consumed_but_all_of_its_content_must_be_valid() {
    let options = DecodingOptions::default();
    assert_eq!(
        Asn1Boolean::decode_inner(&[0x80, 1, 0xff, 0], &mut DecodingContext::new(&options)),
        Ok((3, Asn1Boolean::from(true)))
    );
    assert_eq!(
        Asn1Null::decode_inner(&[0x80, 0, 0], &mut DecodingContext::new(&options)),
        Ok((2, Asn1Null))
    );
    assert_eq!(
        Asn1Boolean::decode_inner(&[0x80, 2, 0xff, 0], &mut DecodingContext::new(&options)),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        Asn1Null::decode_inner(&[0x80, 1, 0], &mut DecodingContext::new(&options)),
        Err(Asn1Error::MalformedValue)
    );
    assert_eq!(
        Asn1Boolean::decode_inner(&[0xa0, 3, 1, 1, 0xff], &mut DecodingContext::new(&options)),
        Err(Asn1Error::UnexpectedTag)
    );
}

#[test]
fn content_and_full_tlv_traits_can_be_implemented_independently_with_borrowed_values() {
    #[derive(Debug, PartialEq)]
    struct Borrowed<'a>(&'a [u8]);
    impl<'a> DecodeContent<'a> for Borrowed<'a> {
        fn decode_content(value: &'a [u8], _: &mut DecodingContext<'_>) -> Result<Self, Asn1Error> {
            Ok(Self(value))
        }

        fn decode_content_der(
            value: &'a [u8],
            context: &mut crate::DecodingContext<'_>,
        ) -> Result<Self, crate::Asn1Error> {
            Self::decode_content(value, context)
        }
    }
    // This explicit implementation would conflict with the former blanket impl.
    impl<'a> DecodeInner<'a> for Borrowed<'a> {
        fn decode_inner(
            buff: &'a [u8],
            context: &mut DecodingContext<'_>,
        ) -> Result<(usize, Self), Asn1Error> {
            let element = Asn1Ref::parse(buff, context)?;
            Ok((
                element.total_len(),
                Self::decode_content(element.value(), context)?,
            ))
        }
        fn decode_inner_der(
            buff: &'a [u8],
            context: &mut DecodingContext<'_>,
        ) -> Result<(usize, Self), Asn1Error> {
            let element = Asn1Ref::parse_der(buff, context)?;
            Ok((
                element.total_len(),
                Self::decode_content_der(element.value(), context)?,
            ))
        }
    }
    impl<'a> crate::Decode<'a> for Borrowed<'a> {
        fn decode(
            buff: &'a [u8],
            options: &crate::DecodingOptions,
        ) -> Result<(usize, Self), crate::Asn1Error> {
            <Self as crate::DecodeInner<'a>>::decode_inner(
                buff,
                &mut crate::DecodingContext::new(options),
            )
        }
    }

    struct ContentOnly;
    impl<'a> DecodeContent<'a> for ContentOnly {
        fn decode_content(_: &'a [u8], _: &mut DecodingContext<'_>) -> Result<Self, Asn1Error> {
            Ok(Self)
        }

        fn decode_content_der(
            value: &'a [u8],
            context: &mut crate::DecodingContext<'_>,
        ) -> Result<Self, crate::Asn1Error> {
            Self::decode_content(value, context)
        }
    }
    let wire = [0x80, 1, 42];
    let options = DecodingOptions::default();
    let value = Asn1Ref::parse(&wire, &mut DecodingContext::new(&options))
        .unwrap()
        .decode_as::<Borrowed<'_>>(&mut DecodingContext::new(&options))
        .unwrap();
    assert_eq!(value.0.as_ptr(), wire[2..].as_ptr());
    assert!(
        Fields::new(&wire, &mut DecodingContext::new(&options))
            .unwrap()
            .implicit::<ContentOnly>(&[0x80])
            .is_ok()
    );
}

#[test]
fn constructed_implicit_strings_dispatch_by_form_and_validate_component_tags() {
    let options = DecodingOptions::default();
    for wire in [
        &[0xa0, 6, 4, 1, 0xaa, 4, 1, 0xbb][..],
        &[0xa0, 0x80, 4, 1, 0xaa, 4, 1, 0xbb, 0, 0],
    ] {
        let (used, value) =
            Asn1OctetString::decode_inner(wire, &mut DecodingContext::new(&options)).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(value.as_bytes(), &[0xaa, 0xbb]);
        let mut context = DecodingContext::new(&options);
        let mut fields = Fields::new(wire, &mut context).unwrap();
        assert_eq!(
            fields
                .implicit_constructed::<Asn1OctetString>(&[0x80])
                .unwrap(),
            value
        );
        fields.finish().unwrap();
    }
    assert_eq!(
        Asn1OctetString::decode_inner(&[0xa0, 3, 2, 1, 42], &mut DecodingContext::new(&options)),
        Err(Asn1Error::UnexpectedTag)
    );
    assert_eq!(
        Asn1BitString::decode_inner(&[0xa0, 3, 4, 1, 0], &mut DecodingContext::new(&options)),
        Err(Asn1Error::UnexpectedTag)
    );
}

#[test]
fn content_limits_apply_at_tlv_and_direct_content_entries() {
    let options = DecodingOptions::new(4, 2, 2);
    assert!(
        Asn1OctetString::decode_inner(&[0x80, 2, 1, 2], &mut DecodingContext::new(&options))
            .is_ok()
    );
    assert_eq!(
        Asn1OctetString::decode_inner(&[0x80, 3, 1, 2, 3], &mut DecodingContext::new(&options)),
        Err(Asn1Error::ContentLengthExceeded)
    );
    assert_eq!(
        Asn1OctetString::decode_content(&[1, 2, 3], &mut DecodingContext::new(&options)),
        Err(Asn1Error::ContentLengthExceeded)
    );
    assert_eq!(
        Asn1OctetString::decode_constructed(&[4, 1, 0], &mut DecodingContext::new(&options)),
        Err(Asn1Error::ContentLengthExceeded)
    );
    assert_eq!(
        Asn1Ref::parse(
            &[0x30, 0x80, 5, 0, 5, 0, 0, 0],
            &mut DecodingContext::new(&options)
        )
        .err(),
        Some(Asn1Error::ContentLengthExceeded)
    );
}

#[test]
fn child_limits_apply_to_definite_and_indefinite_values_and_iteration_stops_after_error() {
    let options = DecodingOptions::new(4, 32, 1);
    for wire in [&[0x30, 4, 5, 0, 5, 0][..], &[0x30, 0x80, 5, 0, 5, 0, 0, 0]] {
        assert_eq!(
            Asn1SequenceOf::<Asn1Null>::decode_inner(wire, &mut DecodingContext::new(&options)),
            Err(Asn1Error::ChildrenExceeded)
        );
    }
    let mut context_0 = DecodingContext::new(&options);
    let mut children = Children::new(&[5, 0, 5, 0], &mut context_0);
    assert!(children.next().unwrap().is_ok());
    assert_eq!(
        children.next().unwrap().err(),
        Some(Asn1Error::ChildrenExceeded)
    );
    assert!(children.next().is_none());
    let zero = DecodingOptions::new(1, 0, 0);
    assert!(
        Asn1SequenceOf::<Asn1Null>::decode_inner(&[0x30, 0], &mut DecodingContext::new(&zero))
            .is_ok()
    );
    assert!(Asn1Null::decode_inner(&[5, 0], &mut DecodingContext::new(&zero)).is_ok());
}

#[test]
fn nested_decoders_preserve_custom_limits_and_spend_depth_per_constructed_layer() {
    let nested = [0x30, 4, 0x30, 2, 5, 0];
    type Nested = Asn1SequenceOf<Asn1SequenceOf<Asn1Null>>;
    assert!(
        Nested::decode_inner(
            &nested,
            &mut DecodingContext::new(&DecodingOptions::new(2, 4, 1))
        )
        .is_ok()
    );
    assert_eq!(
        Nested::decode_inner(
            &nested,
            &mut DecodingContext::new(&DecodingOptions::new(1, 4, 1))
        ),
        Err(Asn1Error::DepthExceeded)
    );
    let too_many = [0x30, 6, 0x30, 4, 5, 0, 5, 0];
    assert_eq!(
        Nested::decode_inner(
            &too_many,
            &mut DecodingContext::new(&DecodingOptions::new(2, 6, 1))
        ),
        Err(Asn1Error::ChildrenExceeded)
    );
}

#[test]
fn parsed_elements_require_custom_decoders_to_consume_the_complete_element() {
    #[derive(Debug, PartialEq)]
    struct Partial;
    impl<'a> DecodeInner<'a> for Partial {
        fn decode_inner(
            _: &'a [u8],
            _: &mut DecodingContext<'_>,
        ) -> Result<(usize, Self), Asn1Error> {
            Ok((0, Self))
        }
        fn decode_inner_der(
            _: &'a [u8],
            _context: &mut DecodingContext<'_>,
        ) -> Result<(usize, Self), Asn1Error> {
            Ok((0, Self))
        }
    }
    impl<'a> crate::Decode<'a> for Partial {
        fn decode(
            buff: &'a [u8],
            options: &crate::DecodingOptions,
        ) -> Result<(usize, Self), crate::Asn1Error> {
            <Self as crate::DecodeInner<'a>>::decode_inner(
                buff,
                &mut crate::DecodingContext::new(options),
            )
        }
    }

    let options = DecodingOptions::default();
    let element = Asn1Ref::parse(&[5, 0], &mut DecodingContext::new(&options)).unwrap();
    assert_eq!(
        element.decode_as::<Partial>(&mut DecodingContext::new(&options)),
        Err(Asn1Error::TrailingData)
    );
    assert_eq!(
        Fields::new(&[5, 0], &mut DecodingContext::new(&options))
            .unwrap()
            .required::<Partial>(&[5]),
        Err(Asn1Error::TrailingData)
    );
}

#[test]
fn opaque_values_keep_parsed_boundaries_when_the_original_budget_exceeds_the_default() {
    let mut wire = Vec::new();
    for _ in 0..40 {
        wire.extend_from_slice(&[0x30, 0x80]);
    }
    wire.extend_from_slice(&[5, 0]);
    for _ in 0..40 {
        wire.extend_from_slice(&[0, 0]);
    }
    let options = DecodingOptions::new(40, wire.len(), 1);
    let (used, any) = Asn1Any::decode_inner(&wire, &mut DecodingContext::new(&options)).unwrap();
    assert_eq!(used, wire.len());
    assert_eq!(any.as_ref().raw(), wire);
    assert_eq!(any.as_ref().value(), &wire[2..wire.len() - 2]);
    assert_eq!(
        any.encode_to_vec(&EncodingOptions::new(EncodingType::Der))
            .unwrap(),
        wire
    );
}
