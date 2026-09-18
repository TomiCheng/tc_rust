use alloc::vec::Vec;

use super::cer_common::{primitive_tag, CER_SEGMENT_LEN, SEGMENT_RULES};
use crate::traits::encode::{len_octets, write_len};
use crate::{
    Asn1Error, Asn1OctetString, Children, Decode, DecodeConstructed, DecodeContent, DecodeInner,
    DecodingContext, DecodingOptions, Encode, EncodeContent, EncodeTagged, EncodingOptions,
    EncodingType, LengthForm,
};

/// The constructed form of an OCTET STRING: a series of primitive segments.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1OctetStringConstructed {
    segments: Vec<Asn1OctetString>,
}

impl Asn1OctetStringConstructed {
    pub const TAG: &'static [u8] = super::tag::CONSTRUCTED_OCTET_STRING;

    pub fn segments(&self) -> &[Asn1OctetString] {
        &self.segments
    }

    /// Reads one constructed TLV whose identifier is `tag` rather than 24. The
    /// character string types are encoded as IMPLICIT OCTET STRING (X.690 §8.23),
    /// so their constructed forms (36 for IA5String, 2C for UTF8String, ...) carry
    /// the same OCTET STRING segments; validate the joined bytes afterwards.
    /// Variable time: branches only on the encoding structure.
    pub fn decode_tagged(
        tag: &[u8],
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != tag || !element.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_constructed(element.value(), context)?;
        Ok((element.total_len(), value))
    }

    /// Splits a value into segments of at most `segment_len` octets (at least 1).
    /// Variable time: branches only on the value's length.
    pub fn split(value: &Asn1OctetString, segment_len: usize) -> Self {
        let segments = value
            .as_bytes()
            .chunks(segment_len.max(1))
            .map(Asn1OctetString::new)
            .collect();
        Self { segments }
    }

    /// Concatenates the segments back into one value.
    /// Variable time: branches only on the segment count.
    pub fn join(&self) -> Asn1OctetString {
        let mut bytes = Vec::new();
        for segment in &self.segments {
            bytes.extend_from_slice(segment.as_bytes());
        }
        Asn1OctetString::from(bytes)
    }

    /// Length of the constructed TLV: `tag|0x20`, length or `80`, segments, EOC.
    pub(crate) fn constructed_len(&self, tag: &[u8], form: LengthForm) -> usize {
        let content = self.content_len(&SEGMENT_RULES);
        tag.len()
            + match form {
                LengthForm::Definite => len_octets(content) + content,
                LengthForm::Indefinite => 1 + content + 2,
            }
    }

    /// Writes the constructed TLV with the given length form.
    /// Variable time: branches only on the encoding structure.
    pub(crate) fn encode_constructed(
        &self,
        tag: &[u8],
        form: LengthForm,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        let total = self.constructed_len(tag, form);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        out[..tag.len()].copy_from_slice(tag);
        out[0] |= 0x20;
        let mut at = tag.len();
        match form {
            LengthForm::Definite => at += write_len(self.content_len(&SEGMENT_RULES), &mut out[at..]),
            LengthForm::Indefinite => {
                out[at] = 0x80;
                at += 1;
            }
        }
        at += self.encode_content(&SEGMENT_RULES, &mut out[at..])?;
        if form == LengthForm::Indefinite {
            out[at..].fill(0);
            at += 2;
        }
        debug_assert_eq!(at, total, "constructed_len and encode_constructed disagree");
        Ok(total)
    }
}

impl DecodeConstructed for Asn1OctetStringConstructed {
    /// Contents of a constructed OCTET STRING; nested constructed segments are
    /// flattened (X.690 §8.7).
    /// Variable time: branches only on the encoding structure.
    fn decode_constructed(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let mut children = Children::new(value, context.enter()?);
        let mut segments: Vec<Asn1OctetString> = Vec::new();
        while let Some(child) = children.next() {
            let child = child?;
            if child.tag() == Asn1OctetString::TAG {
                segments.push(Asn1OctetString::decode_content(child.value(), children.context())?);
            } else if child.tag() == Self::TAG {
                let nested = Self::decode_constructed(child.value(), children.context())?;
                segments.extend(nested.segments);
            } else {
                return Err(Asn1Error::UnexpectedTag);
            }
        }
        Ok(Self { segments })
    }
}

impl DecodeInner for Asn1OctetStringConstructed {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        Self::decode_tagged(Self::TAG, buff, context)
    }

    fn decode_inner_der(_: &[u8], _: &mut DecodingContext) -> Result<(usize, Self), Asn1Error> {
        // The constructed form is never DER (X.690 §10.2).
        Err(Asn1Error::NotDer)
    }
}

impl Decode for Asn1OctetStringConstructed {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl EncodeContent for Asn1OctetStringConstructed {
    /// The segment TLVs back to back, without the outer header or EOC.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.encoded_len(&SEGMENT_RULES))
            .sum()
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let total = self.content_len(rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        let mut at = 0;
        for segment in &self.segments {
            at += segment.encode(&SEGMENT_RULES, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for Asn1OctetStringConstructed {
    /// `tag` is the base identifier; the constructed bit is set or cleared to
    /// match the form actually written. BER keeps the segments as given; DER has
    /// no constructed form, so the value is written primitive; CER writes it
    /// primitive up to 1000 contents octets and otherwise re-segments at 1000
    /// with indefinite length (X.690 §9.2).
    /// Variable time: branches only on the encoding structure.
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        match rules.encoding_type() {
            EncodingType::Ber(form) => self.constructed_len(tag, form),
            EncodingType::Der => self.join().encoded_len_tagged(&primitive_tag(tag), rules),
            EncodingType::Cer => {
                let value = self.join();
                if value.as_bytes().len() <= CER_SEGMENT_LEN {
                    value.encoded_len_tagged(&primitive_tag(tag), rules)
                } else {
                    Self::split(&value, CER_SEGMENT_LEN).constructed_len(tag, LengthForm::Indefinite)
                }
            }
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        match rules.encoding_type() {
            EncodingType::Ber(form) => self.encode_constructed(tag, form, out),
            EncodingType::Der => self.join().encode_tagged(&primitive_tag(tag), rules, out),
            EncodingType::Cer => {
                let value = self.join();
                if value.as_bytes().len() <= CER_SEGMENT_LEN {
                    value.encode_tagged(&primitive_tag(tag), rules, out)
                } else {
                    Self::split(&value, CER_SEGMENT_LEN).encode_constructed(
                        tag,
                        LengthForm::Indefinite,
                        out,
                    )
                }
            }
        }
    }
}

impl Encode for Asn1OctetStringConstructed {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
