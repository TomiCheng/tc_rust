//! CER string segmentation and shared encoding overrides.

use crate::encoding::{default_encode, default_encoded_len, len_octets, write_len};
use crate::{Asn1Error, EncodeContent, EncodingOptions, EncodingType};

/// Length of a CER string TLV. Variable time: branches only on the encoding structure.
pub(crate) fn segmented_len(tag: &[u8], universal_tag: &[u8], contents_len: usize) -> usize {
    if contents_len <= 1000 {
        return tag.len() + len_octets(contents_len) + contents_len;
    }
    let full = contents_len / 1000;
    let rest = contents_len % 1000;
    tag.len()
        + 3
        + full * (universal_tag.len() + 3 + 1000)
        + if rest == 0 {
            0
        } else {
            universal_tag.len() + len_octets(rest) + rest
        }
}

/// Writes primitive segments with their universal tag, even under IMPLICIT tagging.
/// Variable time: branches only on the encoding structure.
pub(crate) fn encode_segmented(
    tag: &[u8],
    universal_tag: &[u8],
    contents: &[u8],
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    let total = segmented_len(tag, universal_tag, contents.len());
    let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
    out[..tag.len()].copy_from_slice(tag);
    if contents.len() <= 1000 {
        out[0] &= !0x20;
        let at = tag.len() + write_len(contents.len(), &mut out[tag.len()..]);
        out[at..].copy_from_slice(contents);
        return Ok(total);
    }
    out[0] |= 0x20;
    out[tag.len()] = 0x80;
    let mut at = tag.len() + 1;
    for segment in contents.chunks(1000) {
        out[at..at + universal_tag.len()].copy_from_slice(universal_tag);
        at += universal_tag.len();
        at += write_len(segment.len(), &mut out[at..]);
        out[at..at + segment.len()].copy_from_slice(segment);
        at += segment.len();
    }
    out[at..].fill(0);
    Ok(total)
}

/// Computes the wire length from the encoded contents, including CER segment headers.
/// Variable time: branches only on the encoding structure.
pub(crate) fn string_len<T: EncodeContent + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: &EncodingOptions,
) -> usize {
    if rules.encoding_type() == EncodingType::Cer
        && value.content_len(&EncodingOptions::new(EncodingType::Der)) > 1000
    {
        tag.len() + 3 + value.content_len(rules)
    } else {
        default_encoded_len(value, tag, rules)
    }
}

/// Wraps already segmented CER contents with the constructed outer header and EOC.
/// Variable time: branches only on the encoding structure.
pub(crate) fn encode_string<T: EncodeContent + ?Sized>(
    value: &T,
    tag: &[u8],
    rules: &EncodingOptions,
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    if rules.encoding_type() != EncodingType::Cer
        || value.content_len(&EncodingOptions::new(EncodingType::Der)) <= 1000
    {
        return default_encode(value, tag, rules, out);
    }
    let total = string_len(value, tag, rules);
    let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
    out[..tag.len()].copy_from_slice(tag);
    out[0] |= 0x20;
    out[tag.len()] = 0x80;
    let at = tag.len() + 1;
    let written = value.encode_content(rules, &mut out[at..total - 2])?;
    debug_assert_eq!(
        at + written + 2,
        total,
        "segmented string content length disagrees"
    );
    out[total - 2..].fill(0);
    Ok(total)
}

macro_rules! cer_string_encode {
    () => {
        /// Variable time: branches only on the encoding structure.
        fn encoded_len_tagged(&self, tag: &[u8], rules: &$crate::EncodingOptions) -> usize {
            $crate::segments::string_len(self, tag, rules)
        }
        /// Variable time: branches only on the encoding structure.
        fn encode_tagged(
            &self,
            tag: &[u8],
            rules: &$crate::EncodingOptions,
            out: &mut [u8],
        ) -> Result<usize, $crate::Asn1Error> {
            $crate::segments::encode_string(self, tag, rules, out)
        }
    };
}
pub(crate) use cer_string_encode;

/// Content length for a string, including CER segment headers but no outer header or EOC.
/// Variable time: public values only; no constant-time alternative is provided.
pub(crate) fn string_content_len(len: usize, rules: &EncodingOptions) -> usize {
    if rules.encoding_type() == EncodingType::Cer && len > 1000 {
        // With no outer tag, the full encoding adds one length octet and two EOC octets.
        segmented_len(&[], crate::tag::OCTET_STRING, len) - 3
    } else {
        len
    }
}

/// Write primitive contents or CER segment TLVs, leaving the output tail unchanged.
/// Variable time: public values only; no constant-time alternative is provided.
pub(crate) fn encode_string_content(
    len: usize,
    rules: &EncodingOptions,
    out: &mut [u8],
    write_primitive: impl FnOnce(&mut [u8]) -> Result<usize, Asn1Error>,
) -> Result<usize, Asn1Error> {
    let total = string_content_len(len, rules);
    let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
    if rules.encoding_type() != EncodingType::Cer || len <= 1000 {
        return write_primitive(out);
    }
    let mut contents = alloc::vec![0; len];
    let written = write_primitive(&mut contents)?;
    debug_assert_eq!(written, len, "primitive string content length disagrees");
    let mut at = 0;
    for segment in contents.chunks(1000) {
        out[at] = crate::tag::OCTET_STRING[0];
        at += 1;
        at += write_len(segment.len(), &mut out[at..]);
        out[at..at + segment.len()].copy_from_slice(segment);
        at += segment.len();
    }
    debug_assert_eq!(at, total, "segmented string content length disagrees");
    Ok(at)
}

macro_rules! cer_string_content_encode {
    () => {
        /// Content length, including CER segment headers but no outer header or EOC.
        /// Variable-time contract: public values only; no constant-time alternative is provided.
        fn content_len(&self, rules: &$crate::EncodingOptions) -> usize {
            $crate::segments::string_content_len(self.primitive_content_len(rules), rules)
        }

        /// Write primitive contents or CER segment TLVs, leaving any output tail unchanged.
        /// Variable-time contract: public values only; no constant-time alternative is provided.
        fn encode_content(
            &self,
            rules: &$crate::EncodingOptions,
            out: &mut [u8],
        ) -> Result<usize, $crate::Asn1Error> {
            $crate::segments::encode_string_content(
                self.primitive_content_len(rules),
                rules,
                out,
                |out| self.encode_primitive_content(rules, out),
            )
        }
    };
}
pub(crate) use cer_string_content_encode;

/// Concatenates primitive segment contents, including nested constructed segments.
/// Callers validate the joined bytes, so multioctet characters can cross boundaries.
/// Variable time: branches only on the encoding structure.
pub(crate) fn join_segments(
    tag: &[u8],
    value: &[u8],
    context: &mut crate::DecodingContext<'_>,
) -> Result<alloc::vec::Vec<u8>, Asn1Error> {
    fn append(
        tag: &[u8],
        value: &[u8],
        context: &mut crate::DecodingContext<'_>,
        joined: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), Asn1Error> {
        context.with_child(|context| {
            let mut children = crate::asn1_ref::ChildCursor::new(value, context.options());
            while let Some(child) = children.next(context) {
                let child = child?;
                if child.tag() == tag {
                    joined.extend_from_slice(child.value());
                } else if crate::asn1_ref::is_constructed_form(child.tag(), tag) {
                    append(tag, child.value(), context, joined)?;
                } else {
                    return Err(Asn1Error::UnexpectedTag);
                }
            }
            Ok(())
        })
    }
    let mut joined = alloc::vec::Vec::new();
    append(tag, value, context, &mut joined)?;
    Ok(joined)
}

macro_rules! constructed_string_decode {
    ($name:ty) => {
        impl<'a> $crate::DecodeConstructed<'a> for $name {
            /// Joins OCTET STRING segments before validating the character encoding.
            /// Variable time: branches only on the encoding structure.
            fn decode_constructed(
                value: &'a [u8],
                context: &mut $crate::DecodingContext<'_>,
            ) -> Result<Self, $crate::Asn1Error> {
                context.options().check_content_len(value.len())?;
                let joined =
                    $crate::segments::join_segments($crate::tag::OCTET_STRING, value, context)?;
                <Self as $crate::DecodeContent<'_>>::decode_content(&joined, context)
            }
        }
    };
}
pub(crate) use constructed_string_decode;

#[cfg(test)]
mod tests {
    use crate::DecodingOptions;
    use crate::*;

    #[test]
    fn cer_external_alternatives_and_long_descriptors_round_trip() {
        for encoding in [
            ExternalEncoding::OctetAligned(Asn1OctetString::new(&[0xaa; 1001])),
            ExternalEncoding::Arbitrary(Asn1BitString::from_bits(&[0xf0; 1000], 7996)),
            ExternalEncoding::SingleAsn1Type(alloc::boxed::Box::new(
                Asn1OctetString::new(&[0xaa; 1001]).into(),
            )),
        ] {
            let value = Asn1External::new(
                None,
                None,
                Some(Asn1ObjectDescriptor::new(&[b'A'; 1001])),
                encoding,
            );
            let cer = value
                .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap();
            assert_eq!(&cer[..4], &[0x28, 0x80, 0x27, 0x80]);
            assert_eq!(
                Asn1External::decode(&cer, &DecodingOptions::default()).map(|(_, value)| value),
                Ok(value.clone())
            );
            assert_eq!(
                Asn1Object::decode(&cer, &DecodingOptions::default()).map(|(_, value)| value),
                Ok(value.clone().into())
            );
            assert_eq!(
                {
                    let input: &[u8] = &cer;
                    Asn1External::decode(input, &DecodingOptions::default()).and_then(
                        |(used, value)| {
                            if used != input.len() {
                                Err(crate::Asn1Error::TrailingData)
                            } else if value.encode_to_vec(&crate::EncodingOptions::new(
                                crate::EncodingType::Der,
                            ))? != input
                            {
                                Err(crate::Asn1Error::NotDer)
                            } else {
                                Ok(value)
                            }
                        },
                    )
                },
                Err(Asn1Error::NotDer)
            );
        }
    }

    #[test]
    fn cer_bit_segments_handle_exact_data_multiples_and_preserve_unused_bits() {
        for len in [999, 1000, 1998, 1999, 2997] {
            for unused in [0, 1, 7] {
                let value = Asn1BitString::from_bits(&alloc::vec![0xff; len], len * 8 - unused);
                let wire = value
                    .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                    .unwrap();
                assert_eq!(
                    Asn1BitString::decode(&wire, &DecodingOptions::default())
                        .map(|(_, value)| value),
                    Ok(value.clone())
                );
                if len >= 1000 {
                    let element = Asn1Ref::parse(
                        &wire,
                        &mut DecodingContext::new(&DecodingOptions::default()),
                    )
                    .unwrap();
                    let parts: alloc::vec::Vec<_> = element
                        .children(&mut DecodingContext::new(&DecodingOptions::default()))
                        .map(Result::unwrap)
                        .collect();
                    for part in &parts[..parts.len() - 1] {
                        assert_eq!(part.tag(), tag::BIT_STRING);
                        assert_eq!(part.value().len(), 1000);
                        assert_eq!(part.value()[0], 0);
                    }
                    assert_eq!(parts.last().unwrap().value()[0], unused as u8);
                    assert_eq!(
                        {
                            let input: &[u8] = &wire;
                            Asn1BitString::decode(input, &DecodingOptions::default()).and_then(
                                |(used, value)| {
                                    if used != input.len() {
                                        Err(crate::Asn1Error::TrailingData)
                                    } else if value.encode_to_vec(&crate::EncodingOptions::new(
                                        crate::EncodingType::Der,
                                    ))? != input
                                    {
                                        Err(crate::Asn1Error::NotDer)
                                    } else {
                                        Ok(value)
                                    }
                                },
                            )
                        },
                        Err(Asn1Error::NotDer)
                    );
                } else {
                    assert_eq!(
                        {
                            let input: &[u8] = &wire;
                            Asn1BitString::decode(input, &DecodingOptions::default()).and_then(
                                |(used, value)| {
                                    if used != input.len() {
                                        Err(crate::Asn1Error::TrailingData)
                                    } else if value.encode_to_vec(&crate::EncodingOptions::new(
                                        crate::EncodingType::Der,
                                    ))? != input
                                    {
                                        Err(crate::Asn1Error::NotDer)
                                    } else {
                                        Ok(value)
                                    }
                                },
                            )
                        },
                        Ok(value)
                    );
                }
            }
        }
    }

    #[test]
    fn cer_set_of_sorts_complete_encodings_and_rejects_der_round_trip_validation() {
        let set = Asn1SetOf::from(alloc::vec![
            Asn1Integer::from(5_u8),
            Asn1Integer::from(3_u8)
        ]);
        let expected = [0x31, 0x80, 2, 1, 3, 2, 1, 5, 0, 0];
        assert_eq!(
            set.encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap(),
            expected
        );
        assert_eq!(
            {
                let input: &[u8] = &expected;
                Asn1SetOf::<Asn1Integer>::decode(input, &DecodingOptions::default()).and_then(
                    |(used, value)| {
                        if used != input.len() {
                            Err(crate::Asn1Error::TrailingData)
                        } else if value
                            .encode_to_vec(&crate::EncodingOptions::new(crate::EncodingType::Der))?
                            != input
                        {
                            Err(crate::Asn1Error::NotDer)
                        } else {
                            Ok(value)
                        }
                    },
                )
            },
            Err(Asn1Error::NotDer)
        );
        let decoded = Asn1SetOf::<Asn1Integer>::decode(&expected, &DecodingOptions::default())
            .map(|(_, value)| value)
            .unwrap();
        assert_eq!(
            decoded.members(),
            &[Asn1Integer::from(3_u8), Asn1Integer::from(5_u8)]
        );
        let sequence = Asn1Object::Sequence(alloc::vec![
            Asn1Integer::from(42_u8).into(),
            Asn1Object::Null
        ]);
        assert_eq!(
            {
                let input: &[u8] = &sequence
                    .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                    .unwrap();
                Asn1Object::decode(input, &DecodingOptions::default()).and_then(|(used, value)| {
                    if used != input.len() {
                        Err(crate::Asn1Error::TrailingData)
                    } else if value
                        .encode_to_vec(&crate::EncodingOptions::new(crate::EncodingType::Der))?
                        != input
                    {
                        Err(crate::Asn1Error::NotDer)
                    } else {
                        Ok(value)
                    }
                })
            },
            Err(Asn1Error::NotDer)
        );
    }

    fn check_string<T>(value: T)
    where
        T: for<'a> Decode<'a>
            + for<'a> DecodeInner<'a>
            + Encode
            + Clone
            + core::fmt::Debug
            + PartialEq
            + Into<Asn1Object>,
    {
        let len = value.content_len(&EncodingOptions::new(EncodingType::Der));
        let cer = value
            .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
            .unwrap();
        let tree: Asn1Object = value.clone().into();
        assert_eq!(
            tree.encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap(),
            cer
        );
        assert_eq!(
            T::decode(&cer, &DecodingOptions::default())
                .map(|(_, value)| value)
                .unwrap(),
            value
        );
        assert_eq!(
            Asn1Object::decode(&cer, &DecodingOptions::default())
                .map(|(_, value)| value)
                .unwrap(),
            tree
        );
        let der = value
            .encode_to_vec(&EncodingOptions::new(EncodingType::Der))
            .unwrap();
        assert_eq!(
            value
                .encode_to_vec(&EncodingOptions::new(EncodingType::Ber(
                    crate::LengthForm::Definite
                )))
                .unwrap(),
            der
        );
        if len > 1000 {
            assert_eq!(cer[0], der[0] | 0x20);
            assert_eq!(cer[1], 0x80);
            let outer =
                Asn1Ref::parse(&cer, &mut DecodingContext::new(&DecodingOptions::default()))
                    .unwrap();
            let parts: alloc::vec::Vec<_> = outer
                .children(&mut DecodingContext::new(&DecodingOptions::default()))
                .map(Result::unwrap)
                .collect();
            for (index, part) in parts.iter().enumerate() {
                assert_eq!(part.tag(), tag::OCTET_STRING);
                assert!(!part.is_constructed());
                assert_eq!(
                    part.value().len(),
                    if index + 1 == parts.len() {
                        (len - 1) % 1000 + 1
                    } else {
                        1000
                    }
                );
            }
            assert_eq!(
                {
                    let input: &[u8] = &cer;
                    T::decode(input, &DecodingOptions::default()).and_then(|(used, value)| {
                        if used != input.len() {
                            Err(crate::Asn1Error::TrailingData)
                        } else if value
                            .encode_to_vec(&crate::EncodingOptions::new(crate::EncodingType::Der))?
                            != input
                        {
                            Err(crate::Asn1Error::NotDer)
                        } else {
                            Ok(value)
                        }
                    })
                },
                Err(Asn1Error::NotDer)
            );
            assert_eq!(
                {
                    let input: &[u8] = &cer;
                    Asn1Object::decode(input, &DecodingOptions::default()).and_then(
                        |(used, value)| {
                            if used != input.len() {
                                Err(crate::Asn1Error::TrailingData)
                            } else if value.encode_to_vec(&crate::EncodingOptions::new(
                                crate::EncodingType::Der,
                            ))? != input
                            {
                                Err(crate::Asn1Error::NotDer)
                            } else {
                                Ok(value)
                            }
                        },
                    )
                },
                Err(Asn1Error::NotDer)
            );
        } else {
            assert_eq!(cer, der);
            assert_eq!(
                {
                    let input: &[u8] = &cer;
                    T::decode(input, &DecodingOptions::default()).and_then(|(used, value)| {
                        if used != input.len() {
                            Err(crate::Asn1Error::TrailingData)
                        } else if value
                            .encode_to_vec(&crate::EncodingOptions::new(crate::EncodingType::Der))?
                            != input
                        {
                            Err(crate::Asn1Error::NotDer)
                        } else {
                            Ok(value)
                        }
                    })
                }
                .unwrap(),
                value
            );
        }
        assert_eq!(
            value.encode(
                &EncodingOptions::new(EncodingType::Cer),
                &mut alloc::vec![0; cer.len() - 1]
            ),
            Err(Asn1Error::BufferTooSmall)
        );
    }

    #[test]
    fn every_segmentable_character_type_round_trips_as_a_typed_value_and_object() {
        for count in [0, 1, 999, 1000, 1001, 2000, 2001] {
            let ascii = "1".repeat(count);
            check_string(Asn1Utf8String::new(&ascii));
            check_string(Asn1NumericString::new(&ascii).unwrap());
            check_string(Asn1PrintableString::new(&ascii).unwrap());
            check_string(Asn1Ia5String::new(&ascii).unwrap());
            check_string(Asn1VisibleString::new(&ascii).unwrap());
            check_string(Asn1TeletexString::new(ascii.as_bytes()));
            check_string(Asn1VideotexString::new(ascii.as_bytes()));
            check_string(Asn1GeneralString::new(ascii.as_bytes()));
            check_string(Asn1GraphicString::new(ascii.as_bytes()));
            check_string(Asn1ObjectDescriptor::new(ascii.as_bytes()));
        }
        for count in [0, 1, 249, 250, 251, 499, 500, 501, 1000] {
            check_string(Asn1BmpString::new(&"台".repeat(count)).unwrap());
            check_string(Asn1UniversalString::new(&"🦀".repeat(count)));
        }
    }

    #[test]
    fn joining_segments_validates_character_sets_and_code_units_after_concatenation() {
        assert_eq!(
            Asn1BmpString::decode(
                &[0x3e, 6, 4, 1, 0x53, 4, 1, 0xf0],
                &DecodingOptions::default()
            )
            .map(|(_, value)| value)
            .unwrap()
            .as_str(),
            "台"
        );
        assert_eq!(
            Asn1UniversalString::decode(
                &[0x3c, 8, 4, 1, 0, 4, 3, 0, 0x53, 0xf0],
                &DecodingOptions::default()
            )
            .map(|(_, value)| value)
            .unwrap()
            .as_str(),
            "台"
        );
        assert_eq!(
            Asn1BmpString::decode(&[0x3e, 6, 4, 1, 0xd8, 4, 1, 0], &DecodingOptions::default())
                .map(|(_, value)| value),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1NumericString::decode(&[0x32, 3, 4, 1, b'A'], &DecodingOptions::default())
                .map(|(_, value)| value),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1VisibleString::decode(&[0x3a, 3, 4, 1, 0x7f], &DecodingOptions::default())
                .map(|(_, value)| value),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1Ia5String::decode(&[0x36, 3, 4, 1, 0xff], &DecodingOptions::default())
                .map(|(_, value)| value),
            Err(Asn1Error::MalformedValue)
        );
        let nested = [0x2c, 5, 0x24, 3, 4, 1, b'A'];
        assert_eq!(
            Asn1Utf8String::decode(&nested, &DecodingOptions::new(1, 16 * 1024 * 1024, 65_536))
                .map(|(_, value)| value),
            Err(Asn1Error::DepthExceeded)
        );
        assert_eq!(
            Asn1Utf8String::decode(&nested, &DecodingOptions::new(2, 16 * 1024 * 1024, 65_536))
                .map(|(_, value)| value)
                .unwrap()
                .as_str(),
            "A"
        );
    }

    #[test]
    fn oid_iri_encodings_stay_primitive_even_above_the_cer_string_limit() {
        let label = "a".repeat(1001);
        let absolute = Asn1OidIri::new(&alloc::format!("/ISO/{label}")).unwrap();
        let relative = Asn1RelativeOidIri::new(&label).unwrap();
        for value in [Asn1Object::from(absolute), Asn1Object::from(relative)] {
            let cer = value
                .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap();
            assert_eq!(cer[0] & 0x20, 0);
            assert_eq!(
                cer,
                value
                    .encode_to_vec(&EncodingOptions::new(EncodingType::Der))
                    .unwrap()
            );
            assert_eq!(
                Asn1Object::decode(&cer, &DecodingOptions::default())
                    .map(|(_, value)| value)
                    .unwrap(),
                value
            );
        }
        assert_eq!(
            Asn1OidIri::decode(&[0x3f, 0x23, 0], &DecodingOptions::default())
                .map(|(_, value)| value),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            Asn1RelativeOidIri::decode(&[0x3f, 0x24, 0], &DecodingOptions::default())
                .map(|(_, value)| value),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn cer_embedded_payloads_round_trip_with_indefinite_identification_wrappers() {
        for value in [
            Asn1Object::from(Asn1EmbeddedPdv::new(
                PdvIdentification::Fixed,
                alloc::vec![0xaa; 1001],
            )),
            Asn1Object::from(Asn1CharacterString::new(
                PdvIdentification::Fixed,
                alloc::vec![0xaa; 1001],
            )),
        ] {
            let wire = value
                .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap();
            assert_eq!(&wire[1..10], &[0x80, 0xa0, 0x80, 0x85, 0, 0, 0, 0xa2, 0x80]);
            assert_eq!(
                Asn1Object::decode(&wire, &DecodingOptions::default()).map(|(_, value)| value),
                Ok(value)
            );
        }
    }

    #[test]
    fn cer_string_segmentation_handles_exact_multiples_and_high_implicit_tags() {
        for len in [0, 999, 1000, 1001, 1999, 2000, 2001, 3000] {
            let value = Asn1OctetString::new(&alloc::vec![0xaa; len]);
            let wire = value
                .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap();
            assert_eq!(
                wire.len(),
                value.encoded_len(&EncodingOptions::new(EncodingType::Cer))
            );
            assert_eq!(
                Asn1OctetString::decode(&wire, &DecodingOptions::default()).map(|(_, value)| value),
                Ok(value.clone())
            );
            let tagged = Implicit::new(&[0x9f, 0x81, 0], &value);
            let wire = tagged
                .encode_to_vec(&EncodingOptions::new(EncodingType::Cer))
                .unwrap();
            assert_eq!(wire[0], if len > 1000 { 0xbf } else { 0x9f });
            let options = DecodingOptions::default();
            let mut context = DecodingContext::new(&options);
            let mut fields = Fields::new(&wire, &mut context).unwrap();
            assert_eq!(
                if len > 1000 {
                    fields.implicit_constructed::<Asn1OctetString>(&[0x9f, 0x81, 0])
                } else {
                    fields.implicit::<Asn1OctetString>(&[0x9f, 0x81, 0])
                }
                .unwrap(),
                value
            );
            fields.finish().unwrap();
        }
    }
}
