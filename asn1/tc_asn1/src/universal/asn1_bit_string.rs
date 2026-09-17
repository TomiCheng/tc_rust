use alloc::vec::Vec;

use crate::asn1_ref::Children;
use crate::traits::encode::{default_encode, default_encoded_len, len_octets, write_len};
use crate::{
    Asn1Error, Decode, DecodeConstructed, DecodeContent, DecodeInner, DecodingContext,
    DecodingOptions, Encode, EncodeContent, EncodeTagged, EncodingOptions, EncodingType,
};

/// CER segments hold 1000 content octets; one of them is the unused-bit count.
const CER_SEGMENT_DATA: usize = 999;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1BitString {
    unused_bits: u8,
    bytes: Vec<u8>,
}

impl Asn1BitString {
    pub const TAG: &'static [u8] = super::tag::BIT_STRING;

    pub const CONSTRUCTED_TAG: &'static [u8] = super::tag::CONSTRUCTED_BIT_STRING;

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

    fn cer_segmented(&self, rules: &EncodingOptions) -> bool {
        rules.encoding_type() == EncodingType::Cer && self.bytes.len() >= 1000
    }

    fn segments_len(&self) -> usize {
        self.bytes
            .chunks(CER_SEGMENT_DATA)
            .map(|part| 1 + len_octets(part.len() + 1) + 1 + part.len())
            .sum()
    }

    fn write_segments(&self, out: &mut [u8]) -> usize {
        let mut at = 0;
        let count = self.bytes.len().div_ceil(CER_SEGMENT_DATA);
        for (index, part) in self.bytes.chunks(CER_SEGMENT_DATA).enumerate() {
            out[at] = Self::TAG[0];
            at += 1;
            at += write_len(part.len() + 1, &mut out[at..]);
            out[at] = if index + 1 == count {
                self.unused_bits
            } else {
                0
            };
            at += 1;
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        at
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
        let element = crate::Asn1Ref::parse(buff, context)?;
        let value = if element.tag() == Self::TAG {
            Self::decode_content(element.value(), context)?
        } else if element.tag() == Self::CONSTRUCTED_TAG {
            Self::decode_constructed(element.value(), context)?
        } else {
            return Err(Asn1Error::UnexpectedTag);
        };
        Ok((element.total_len(), value))
    }

    fn decode_inner_der(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // parse_der already reports the constructed form (X.690 §10.2) as NotDer.
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1BitString {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
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
        Ok(Self {
            unused_bits: *unused_bits,
            bytes,
        })
    }

    fn decode_content_der(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let decoded = Self::decode_content(value, context)?;
        if value.len() > 1 && decoded.bytes.last() != value.last() {
            return Err(Asn1Error::NotDer);
        }
        Ok(decoded)
    }
}

impl DecodeConstructed for Asn1BitString {
    fn decode_constructed(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let mut children = Children::new(value, context.enter()?);
        let mut bytes = Vec::new();
        let mut unused_bits = 0;
        while let Some(child) = children.next() {
            if unused_bits != 0 {
                return Err(Asn1Error::MalformedValue);
            }
            let child = child?;
            let part = if child.tag() == Self::TAG {
                Self::decode_content(child.value(), children.context())?
            } else if child.tag() == Self::CONSTRUCTED_TAG {
                Self::decode_constructed(child.value(), children.context())?
            } else {
                return Err(Asn1Error::UnexpectedTag);
            };
            unused_bits = part.unused_bits;
            bytes.extend_from_slice(&part.bytes);
        }
        Ok(Self { bytes, unused_bits })
    }
}

impl EncodeContent for Asn1BitString {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        if self.cer_segmented(rules) {
            self.segments_len()
        } else {
            1 + self.bytes.len()
        }
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let total = self.content_len(rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        if self.cer_segmented(rules) {
            return Ok(self.write_segments(out));
        }
        out[0] = self.unused_bits;
        out[1..].copy_from_slice(&self.bytes);
        Ok(total)
    }
}

impl EncodeTagged for Asn1BitString {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        if !self.cer_segmented(rules) {
            return default_encoded_len(self, tag, rules);
        }
        tag.len() + 1 + self.segments_len() + 2
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if !self.cer_segmented(rules) {
            return default_encode(self, tag, rules, out);
        }
        let total = self.encoded_len_tagged(tag, rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        out[..tag.len()].copy_from_slice(tag);
        out[0] |= 0x20;
        out[tag.len()] = 0x80;
        let start = tag.len() + 1;
        let at = start + self.write_segments(&mut out[start..]);
        out[at..].fill(0);
        Ok(total)
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
