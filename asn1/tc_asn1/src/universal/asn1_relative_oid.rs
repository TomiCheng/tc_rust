use alloc::vec::Vec;
use core::{fmt, str::FromStr};

use super::base128::{push_base128, validate_base128};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1RelativeOid {
    bytes: Vec<u8>,
}

impl Asn1RelativeOid {
    pub const TAG: &'static [u8] = super::tag::RELATIVE_OID;

    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_base128(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn from_arcs(arcs: &[u64]) -> Result<Self, Asn1Error> {
        if arcs.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut bytes = Vec::new();
        for arc in arcs {
            push_base128(&mut bytes, *arc);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn arcs(&self) -> impl Iterator<Item = u64> + '_ {
        self.bytes
            .split_inclusive(|byte| byte & 0x80 == 0)
            .map(|bytes| {
                bytes
                    .iter()
                    .fold(0_u64, |n, b| (n << 7) | u64::from(b & 0x7F))
            })
    }
}
impl FromStr for Asn1RelativeOid {
    type Err = Asn1Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let arcs = text
            .split('.')
            .map(|part| {
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Asn1Error::MalformedValue);
                }
                part.parse::<u64>().map_err(|_| Asn1Error::LengthOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_arcs(&arcs)
    }
}
impl fmt::Display for Asn1RelativeOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.arcs().enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}
impl DecodeInner for Asn1RelativeOid {
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
impl Decode for Asn1RelativeOid {}
impl Tagged for Asn1RelativeOid {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1RelativeOid {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl EncodeContent for Asn1RelativeOid {
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

impl EncodeTagged for Asn1RelativeOid {}

impl Encode for Asn1RelativeOid {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
