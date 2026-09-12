//! CER string segmentation and shared encoding overrides.

use crate::traits::{default_encode, default_encoded_len, len_octets, write_len};
use crate::{Asn1Error, Encode, EncodingType};

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

/// Computes the wire length without materialising the primitive contents.
/// Variable time: branches only on the encoding structure.
pub(crate) fn string_len<T: Encode + ?Sized>(
    value: &T,
    tag: &[u8],
    segment_tag: &[u8],
    rules: EncodingType,
) -> usize {
    if rules == EncodingType::Cer && value.content_len(rules) > 1000 {
        segmented_len(tag, segment_tag, value.content_len(rules))
    } else {
        default_encoded_len(value, tag, rules)
    }
}

/// Materialises long primitive contents once before segmentation.
/// Variable time: branches only on the encoding structure.
pub(crate) fn encode_string<T: Encode + ?Sized>(
    value: &T,
    tag: &[u8],
    segment_tag: &[u8],
    rules: EncodingType,
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    let len = value.content_len(rules);
    if rules != EncodingType::Cer || len <= 1000 {
        return default_encode(value, tag, rules, out);
    }
    if out.len() < segmented_len(tag, segment_tag, len) {
        return Err(Asn1Error::BufferTooSmall);
    }
    let mut contents = alloc::vec![0; len];
    let written = value.encode_content(rules, &mut contents)?;
    debug_assert_eq!(written, len, "primitive string content length disagrees");
    encode_segmented(tag, segment_tag, &contents, out)
}

macro_rules! cer_string_encode {
    () => {
        /// Variable time: branches only on the encoding structure.
        fn encoded_len_tagged(&self, tag: &[u8], rules: $crate::EncodingType) -> usize {
            $crate::segments::string_len(self, tag, $crate::tag::OCTET_STRING, rules)
        }
        /// Variable time: branches only on the encoding structure.
        fn encode_tagged(
            &self,
            tag: &[u8],
            rules: $crate::EncodingType,
            out: &mut [u8],
        ) -> Result<usize, $crate::Asn1Error> {
            $crate::segments::encode_string(self, tag, $crate::tag::OCTET_STRING, rules, out)
        }
    };
}
pub(crate) use cer_string_encode;

/// Concatenates primitive segment contents, including nested constructed segments.
/// Callers validate the joined bytes, so multioctet characters can cross boundaries.
/// Variable time: branches only on the encoding structure.
pub(crate) fn join_segments(
    tag: &[u8],
    value: &[u8],
    depth: crate::Depth,
) -> Result<alloc::vec::Vec<u8>, Asn1Error> {
    fn append(
        tag: &[u8],
        value: &[u8],
        depth: crate::Depth,
        joined: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), Asn1Error> {
        let depth = depth.descend()?;
        for child in crate::Children::new(value, depth) {
            let child = child?;
            if child.tag() == tag {
                joined.extend_from_slice(child.value());
            } else if crate::asn1_ref::is_constructed_form(child.tag(), tag) {
                append(tag, child.value(), depth, joined)?;
            } else {
                return Err(Asn1Error::UnexpectedTag);
            }
        }
        Ok(())
    }
    let mut joined = alloc::vec::Vec::new();
    append(tag, value, depth, &mut joined)?;
    Ok(joined)
}

macro_rules! constructed_string_decode {
    ($name:ty) => {
        impl<'a> $crate::DecodeConstructed<'a> for $name {
            /// Joins OCTET STRING segments before validating the character encoding.
            /// Variable time: branches only on the encoding structure.
            fn try_decode_constructed(
                value: &'a [u8],
                depth: $crate::Depth,
            ) -> Result<Self, $crate::Asn1Error> {
                let joined =
                    $crate::segments::join_segments($crate::tag::OCTET_STRING, value, depth)?;
                <Self as $crate::DecodeContent<'_>>::try_decode_content(&joined, depth)
            }
        }
    };
}
pub(crate) use constructed_string_decode;

#[cfg(test)]
mod tests {
    use crate::*;

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
            let wire = value.encode_to_vec(EncodingType::Cer).unwrap();
            assert_eq!(&wire[1..10], &[0x80, 0xa0, 0x80, 0x85, 0, 0, 0, 0xa2, 0x80]);
            assert_eq!(
                Asn1Object::try_decode_exact(&wire, Depth::DEFAULT),
                Ok(value)
            );
        }
    }

    #[test]
    fn cer_string_segmentation_handles_exact_multiples_and_high_implicit_tags() {
        for len in [0, 999, 1000, 1001, 1999, 2000, 2001, 3000] {
            let value = Asn1OctetString::new(&alloc::vec![0xaa; len]);
            let wire = value.encode_to_vec(EncodingType::Cer).unwrap();
            assert_eq!(wire.len(), value.encoded_len(EncodingType::Cer));
            assert_eq!(
                Asn1OctetString::try_decode_exact(&wire, Depth::DEFAULT),
                Ok(value.clone())
            );
            let tagged = Implicit::new(&[0x9f, 0x81, 0], &value);
            let wire = tagged.encode_to_vec(EncodingType::Cer).unwrap();
            assert_eq!(wire[0], if len > 1000 { 0xbf } else { 0x9f });
            let mut fields = Fields::new(&wire, Depth::DEFAULT).unwrap();
            assert_eq!(
                fields
                    .implicit::<Asn1OctetString>(&[0x9f, 0x81, 0])
                    .unwrap(),
                value
            );
            fields.finish().unwrap();
        }
    }
}
