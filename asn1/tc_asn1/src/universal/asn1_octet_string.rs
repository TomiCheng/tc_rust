use alloc::vec::Vec;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Asn1OctetString {
    bytes: Vec<u8>,
}

impl Asn1OctetString {
    pub const TAG: &'static [u8] = super::tag::OCTET_STRING;

    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for Asn1OctetString {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl DecodeInner for Asn1OctetString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1OctetString {}

impl DecodeContent for Asn1OctetString {
    /// Any contents are valid, including none.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Ok(Self::new(value))
    }
}

impl EncodeContent for Asn1OctetString {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.bytes.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.bytes.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

impl EncodeTagged for Asn1OctetString {
    /// Always primitive. Under CER a value over 1000 octets cannot be written by
    /// this type: `encode_tagged` returns [`Asn1Error::PrimitiveTooLong`], and the
    /// caller splits it with `Asn1OctetStringConstructed` instead.
    /// Variable time: branches only on the encoding structure.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(self.bytes.len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1OctetString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
