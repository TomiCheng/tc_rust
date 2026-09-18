use alloc::vec::Vec;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1BitString {
    unused_bits: u8,
    bytes: Vec<u8>,
}

impl Asn1BitString {
    pub const TAG: &'static [u8] = super::tag::BIT_STRING;

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            unused_bits: 0,
            bytes: bytes.to_vec(),
        }
    }

    pub fn from_bits(bytes: &[u8], bit_len: usize) -> Self {
        let byte_len = bit_len.div_ceil(8).min(bytes.len());
        let bit_len = bit_len.min(byte_len * 8);
        let unused_bits = (byte_len * 8 - bit_len) as u8;
        let mut bytes = bytes[..byte_len].to_vec();
        mask_unused(&mut bytes, unused_bits);
        Self { unused_bits, bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn unused_bits(&self) -> u8 {
        self.unused_bits
    }

    pub fn bit_len(&self) -> usize {
        self.bytes.len() * 8 - usize::from(self.unused_bits)
    }

    pub fn bit(&self, index: usize) -> bool {
        index < self.bit_len() && self.bytes[index / 8] & (0x80 >> (index % 8)) != 0
    }
}

fn mask_unused(bytes: &mut [u8], unused_bits: u8) {
    if let Some(last) = bytes.last_mut() {
        *last &= 0xFF << unused_bits;
    }
}

impl DecodeInner for Asn1BitString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1BitStringConstructed.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1BitString {}
impl Tagged for Asn1BitString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1BitString {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let (unused_bits, data) = value.split_first().ok_or(Asn1Error::MalformedValue)?;
        if *unused_bits > 7 || (data.is_empty() && *unused_bits != 0) {
            return Err(Asn1Error::MalformedValue);
        }
        let mut bytes = data.to_vec();
        mask_unused(&mut bytes, *unused_bits);
        // X.690 §11.2.1: DER requires the unused bits to be zero.
        if context.is_der() && bytes.last() != data.last() {
            return Err(Asn1Error::NotDer);
        }
        Ok(Self {
            unused_bits: *unused_bits,
            bytes,
        })
    }
}

impl EncodeContent for Asn1BitString {
    /// The primitive contents: unused-bit count followed by the data.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        1 + self.bytes.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..1 + self.bytes.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out[0] = self.unused_bits;
        out[1..].copy_from_slice(&self.bytes);
        Ok(out.len())
    }
}

impl EncodeTagged for Asn1BitString {
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(1 + self.bytes.len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1BitString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
