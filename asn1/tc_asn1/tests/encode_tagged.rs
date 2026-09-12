use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Object, Asn1OctetString, EncodeContent, EncodeTagged,
    EncodingOptions, LengthForm,
};

struct Contents;

impl EncodeContent for Contents {
    fn content_len(&self, _: EncodingOptions) -> usize {
        2
    }

    fn encode_content(&self, _: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out.get_mut(..2)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&[1, 0x23]);
        Ok(2)
    }
}

impl EncodeTagged for Contents {}

#[test]
fn content_and_default_tagged_encoding_work_without_encode() {
    let content: Box<dyn EncodeContent> = Box::new(Contents);
    let tagged: Box<dyn EncodeTagged> = Box::new(Contents);
    for rules in [
        EncodingOptions::Ber(LengthForm::Definite),
        EncodingOptions::Ber(LengthForm::Indefinite),
        EncodingOptions::Cer,
        EncodingOptions::Der,
    ] {
        assert_eq!(
            content.as_ref().encode_content_to_vec(rules).unwrap(),
            [1, 0x23]
        );
        check_encoding(
            tagged.as_ref(),
            &[0x9f, 0x20],
            rules,
            &[0x9f, 0x20, 2, 1, 0x23],
        );
    }
}

fn check_encoding(encoder: &dyn EncodeTagged, tag: &[u8], rules: EncodingOptions, expected: &[u8]) {
    assert_eq!(encoder.encoded_len_tagged(tag, rules), expected.len());
    let mut out = vec![0xaa; expected.len() + 3];
    assert_eq!(
        encoder.encode_tagged(tag, rules, &mut out),
        Ok(expected.len())
    );
    assert_eq!(&out[..expected.len()], expected);
    assert_eq!(&out[expected.len()..], &[0xaa; 3]);
    let mut short = vec![0xaa; expected.len() - 1];
    assert_eq!(
        encoder.encode_tagged(tag, rules, &mut short),
        Err(Asn1Error::BufferTooSmall)
    );
    assert!(short.iter().all(|&byte| byte == 0xaa));
}

#[test]
fn boxed_tagged_encoding_preserves_cer_string_overrides() {
    let mut octets = vec![0xbf, 0x20, 0x80, 4, 0x82, 3, 0xe8];
    octets.extend_from_slice(&[0xaa; 1000]);
    octets.extend_from_slice(&[4, 1, 0xaa, 0, 0]);

    let mut bits = vec![0xbf, 0x20, 0x80, 3, 0x82, 3, 0xe8, 0];
    bits.extend_from_slice(&[0xaa; 999]);
    bits.extend_from_slice(&[3, 2, 0, 0xaa, 0, 0]);

    let values: [(Box<dyn EncodeTagged>, &[u8]); 3] = [
        (Box::new(Asn1OctetString::new(&[0xaa; 1001])), &octets),
        (Box::new(Asn1BitString::from_bytes(&[0xaa; 1000])), &bits),
        (
            Box::new(Asn1Object::from(Asn1OctetString::new(&[0xaa; 1001]))),
            &octets,
        ),
    ];
    for (boxed, expected) in values {
        check_encoding(
            boxed.as_ref(),
            &[0x9f, 0x20],
            EncodingOptions::Cer,
            expected,
        );
    }
}

mod schema_with_result_alias {
    use tc_asn1::{Encode, EncodingOptions, SequenceFields, impl_sequence_encode};

    type Result<T> = core::result::Result<T, tc_asn1::Asn1Error>;

    struct Empty;

    impl SequenceFields for Empty {
        fn fields(&self, _: EncodingOptions, _: &mut dyn FnMut(&dyn Encode)) {}
    }

    impl_sequence_encode!(Empty);

    #[test]
    fn sequence_macro_does_not_capture_the_callers_result_alias() -> Result<()> {
        assert_eq!(Empty.encode_to_vec(EncodingOptions::Der)?, [0x30, 0]);
        Ok(())
    }
}
