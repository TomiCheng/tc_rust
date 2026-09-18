use alloc::vec::Vec;

use super::integer_octets::{minimal_signed, validate_integer_octets};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodingOptions, Tagged,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Integer {
    value: Vec<u8>,
}

impl Asn1Integer {
    pub const TAG: &'static [u8] = super::tag::INTEGER;

    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_integer_octets(bytes)?;
        Ok(Self {
            value: bytes.to_vec(),
        })
    }

    pub fn from_unsigned_bytes(magnitude: &[u8]) -> Self {
        let start = magnitude
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        let significant = &magnitude[start..];
        let mut value = Vec::with_capacity(significant.len() + 1);
        if significant.first().is_none_or(|b| b & 0x80 != 0) {
            value.push(0x00); // 零是單一個 00；最高位為 1 要補符號位元組
        }
        value.extend_from_slice(significant);
        Self { value }
    }

    fn from_signed_bytes(twos_complement: &[u8]) -> Self {
        Self {
            value: minimal_signed(twos_complement).to_vec(),
        }
    }

    /// 原始內容：二補數，可能為負。
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    pub fn is_negative(&self) -> bool {
        self.value[0] & 0x80 != 0
    }

    /// 無號大端序，去掉為了符號補的前導 `00`。負數回錯誤。
    pub fn as_unsigned_bytes(&self) -> Result<&[u8], Asn1Error> {
        if self.is_negative() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(match self.value.as_slice() {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            v => v,
        })
    }

    /// 無號解讀，放不進 `u128` 回 [`Asn1Error::LengthOverflow`]，負數回
    /// [`Asn1Error::MalformedValue`]。
    fn to_u128(&self) -> Result<u128, Asn1Error> {
        let bytes = self.as_unsigned_bytes()?;
        if bytes.len() > 16 {
            return Err(Asn1Error::LengthOverflow);
        }
        Ok(bytes
            .iter()
            .fold(0_u128, |acc, b| (acc << 8) | u128::from(*b)))
    }

    /// 有號解讀，放不進 `i128` 回 [`Asn1Error::LengthOverflow`]。
    fn to_i128(&self) -> Result<i128, Asn1Error> {
        if self.value.len() > 16 {
            return Err(Asn1Error::LengthOverflow);
        }
        let sign: i128 = if self.is_negative() { -1 } else { 0 };
        Ok(self
            .value
            .iter()
            .fold(sign, |acc, b| (acc << 8) | i128::from(*b)))
    }
}

macro_rules! from_unsigned {
    ($($t:ty),*) => {$(
        impl From<$t> for Asn1Integer {
            fn from(n: $t) -> Self {
                Self::from_unsigned_bytes(&n.to_be_bytes())
            }
        }
    )*};
}
macro_rules! from_signed {
    ($($t:ty),*) => {$(
        impl From<$t> for Asn1Integer {
            fn from(n: $t) -> Self {
                Self::from_signed_bytes(&n.to_be_bytes())
            }
        }
    )*};
}
from_unsigned!(u8, u16, u32, u64, u128);
from_signed!(i8, i16, i32, i64, i128);

macro_rules! try_into_unsigned {
    ($($t:ty),*) => {$(
        impl TryFrom<&Asn1Integer> for $t {
            type Error = Asn1Error;
            fn try_from(n: &Asn1Integer) -> Result<Self, Asn1Error> {
                <$t>::try_from(n.to_u128()?).map_err(|_| Asn1Error::LengthOverflow)
            }
        }
    )*};
}
macro_rules! try_into_signed {
    ($($t:ty),*) => {$(
        impl TryFrom<&Asn1Integer> for $t {
            type Error = Asn1Error;
            fn try_from(n: &Asn1Integer) -> Result<Self, Asn1Error> {
                <$t>::try_from(n.to_i128()?).map_err(|_| Asn1Error::LengthOverflow)
            }
        }
    )*};
}
try_into_unsigned!(u8, u16, u32, u64, u128);
try_into_signed!(i8, i16, i32, i64, i128);

impl DecodeInner for Asn1Integer {
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

impl Decode for Asn1Integer {}
impl Tagged for Asn1Integer {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Integer {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl crate::EncodeContent for Asn1Integer {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.value.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.value.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.value);
        Ok(self.value.len())
    }
}

impl crate::EncodeTagged for Asn1Integer {}

impl Encode for Asn1Integer {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}
