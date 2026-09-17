use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use super::base128::{push_base128, validate_base128};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, DecodingOptions, Encode,
    EncodeContent, EncodeTagged, EncodingOptions,
};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1Oid {
    bytes: Vec<u8>,
}

impl Asn1Oid {
    pub const TAG: &'static [u8] = super::tag::OBJECT_IDENTIFIER;

    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_base128(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// 由弧建立，例如 `[1, 2, 840, 113549, 1, 1, 1]`。
    ///
    /// 前兩個弧合併成一個子識別碼：第一個只能是 0、1、2，前兩種情況第二個小於 40。
    pub fn from_arcs(arcs: &[u64]) -> Result<Self, Asn1Error> {
        let [first, second, rest @ ..] = arcs else {
            return Err(Asn1Error::MalformedValue);
        };
        if *first > 2 || (*first < 2 && *second >= 40) {
            return Err(Asn1Error::MalformedValue);
        }
        let head = first
            .checked_mul(40)
            .and_then(|v| v.checked_add(*second))
            .ok_or(Asn1Error::LengthOverflow)?;

        let mut bytes = Vec::new();
        push_base128(&mut bytes, head);
        for arc in rest {
            push_base128(&mut bytes, *arc);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 弧，第一個子識別碼拆回兩個。
    pub fn arcs(&self) -> Arcs<'_> {
        Arcs {
            rest: &self.bytes,
            pending: None,
            first: true,
        }
    }
}

pub struct Arcs<'a> {
    rest: &'a [u8],
    pending: Option<u64>,
    first: bool,
}

impl Iterator for Arcs<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if let Some(second) = self.pending.take() {
            return Some(second);
        }
        if self.rest.is_empty() {
            return None;
        }

        let mut value: u64 = 0;
        let mut consumed = 0;
        for byte in self.rest {
            consumed += 1;
            value = (value << 7) | u64::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                break;
            }
        }
        let is_first = self.first;
        self.first = false;
        self.rest = &self.rest[consumed..];

        if is_first {
            let (first, second) = match value {
                0..=39 => (0, value),
                40..=79 => (1, value - 40),
                _ => (2, value - 80),
            };
            self.pending = Some(second);
            Some(first)
        } else {
            Some(value)
        }
    }
}

impl fmt::Display for Asn1Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, arc) in self.arcs().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl FromStr for Asn1Oid {
    type Err = Asn1Error;

    fn from_str(s: &str) -> Result<Self, Asn1Error> {
        let mut arcs = Vec::new();
        for part in s.split('.') {
            // 空段、非數字、超過 u64 都是壞輸入。
            let arc = part.parse::<u64>().map_err(|_| Asn1Error::MalformedValue)?;
            arcs.push(arc);
        }
        Self::from_arcs(&arcs)
    }
}

impl DecodeInner for Asn1Oid {
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

    fn decode_inner_der(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Oid {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl DecodeContent for Asn1Oid {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }

    fn decode_content_der(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        // X.690 §8.19.2 already requires the shortest base-128 form in BER, so DER adds nothing.
        Self::decode_content(value, context)
    }
}

impl EncodeContent for Asn1Oid {
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

impl EncodeTagged for Asn1Oid {}

impl Encode for Asn1Oid {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
