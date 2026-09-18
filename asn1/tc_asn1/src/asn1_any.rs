use alloc::vec::Vec;

use crate::traits::encode::{len_octets, write_len};
use crate::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, DecodingOptions, Encode,
    EncodeContent, EncodeTagged, EncodingOptions,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Any {
    raw: Vec<u8>,
    length_offset: usize,
    value_offset: usize,
    eoc_offset: usize,
}

impl Asn1Any {
    /// Builds a primitive, definite-length TLV from an identifier and its contents,
    /// for types this crate keeps opaque (TeletexString, GraphicString, ...).
    /// `tag` must be a complete identifier, e.g. `tag::TELETEX_STRING`.
    /// Variable time: branches only on the lengths.
    pub fn primitive(tag: &[u8], value: &[u8]) -> Self {
        let length_offset = tag.len();
        let value_offset = length_offset + len_octets(value.len());
        let mut raw = alloc::vec![0; value_offset + value.len()];
        raw[..length_offset].copy_from_slice(tag);
        write_len(value.len(), &mut raw[length_offset..]);
        raw[value_offset..].copy_from_slice(value);
        Self {
            raw,
            length_offset,
            value_offset,
            eoc_offset: value_offset + value.len(),
        }
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn as_ref(&self) -> Asn1Ref<'_> {
        Asn1Ref::from_validated_parts(
            &self.raw,
            self.length_offset,
            self.value_offset,
            self.eoc_offset,
        )
    }
}

impl From<&Asn1Ref<'_>> for Asn1Any {
    fn from(element: &Asn1Ref<'_>) -> Self {
        let eoc_offset = element.total_len() - element.eoc().len();
        Self {
            raw: element.raw().to_vec(),
            length_offset: element.tag().len(),
            value_offset: eoc_offset - element.value().len(),
            eoc_offset,
        }
    }
}

/// Structural DER check of one element and, recursively, of every element
/// inside a constructed one: identifiers in DER form, lengths definite and
/// shortest. Contents rules that need the type (BOOLEAN FF, BIT STRING unused
/// bits, SET order) are not checked here; Asn1Object covers those.
/// Variable time: branches only on the encoding structure.
fn check_der_structure(element: &Asn1Ref<'_>, context: &mut DecodingContext) -> Result<(), Asn1Error> {
    if !element.is_constructed() {
        return Ok(());
    }
    let mut children = element.children(context)?;
    let mut rest = element.value();
    while let Some(child) = children.next() {
        let child = child?;
        // children() only splits; re-parse each child with the DER checks.
        let checked = Asn1Ref::parse_der(rest, children.context())?;
        check_der_structure(&checked, children.context())?;
        rest = &rest[child.total_len()..];
    }
    Ok(())
}

impl DecodeInner for Asn1Any {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        Ok((element.total_len(), Self::from(&element)))
    }

    fn decode_inner_der(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse_der(buff, context)?;
        check_der_structure(&element, context)?;
        Ok((element.total_len(), Self::from(&element)))
    }
}

impl Decode for Asn1Any {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl EncodeContent for Asn1Any {
    /// The stored contents octets, whatever the rules.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.as_ref().value().len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let value = self.as_ref().value();
        let out = out
            .get_mut(..value.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(value);
        Ok(value.len())
    }
}

/// Under another identifier (IMPLICIT tagging) the contents are re-wrapped with
/// the default header, so an indefinite-length original becomes definite there.
impl EncodeTagged for Asn1Any {}

impl Encode for Asn1Any {
    /// Writes the stored TLV byte for byte, whatever the rules: this type keeps
    /// what was decoded, so a BER original stays BER under DER rules.
    fn encoded_len(&self, _: &EncodingOptions) -> usize {
        self.raw.len()
    }

    fn encode(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.raw.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.raw);
        Ok(self.raw.len())
    }
}
