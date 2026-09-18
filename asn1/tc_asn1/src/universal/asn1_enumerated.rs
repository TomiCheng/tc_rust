use alloc::vec::Vec;

use super::integer_octets::{minimal_signed, validate_integer_octets};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Enumerated {
    value: Vec<u8>,
}

impl Asn1Enumerated {
    pub const TAG: &'static [u8] = super::tag::ENUMERATED;

    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_integer_octets(bytes)?;
        Ok(Self {
            value: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

impl From<u64> for Asn1Enumerated {
    fn from(value: u64) -> Self {
        let mut bytes = [0; 9];
        bytes[1..].copy_from_slice(&value.to_be_bytes());
        Self {
            value: minimal_signed(&bytes).to_vec(),
        }
    }
}

impl From<i64> for Asn1Enumerated {
    /// 由有號值建立最短二補數內容。
    /// 變動時間：依多餘的符號位元組分支。
    fn from(value: i64) -> Self {
        Self {
            value: minimal_signed(&value.to_be_bytes()).to_vec(),
        }
    }
}

impl TryFrom<&Asn1Enumerated> for u64 {
    type Error = Asn1Error;

    /// 轉成無號值；負數回傳 [`Asn1Error::MalformedValue`]，超出範圍回傳
    /// [`Asn1Error::LengthOverflow`]。變動時間：依內容長度、符號與數值範圍分支。
    fn try_from(value: &Asn1Enumerated) -> Result<Self, Self::Error> {
        if value.value[0] & 0x80 != 0 {
            return Err(Asn1Error::MalformedValue);
        }
        // 去掉正號位元組；零會留下空切片，摺疊結果仍是零。
        let bytes = value.value.strip_prefix(&[0]).unwrap_or(&value.value);
        if bytes.len() > 8 {
            return Err(Asn1Error::LengthOverflow);
        }
        Ok(bytes
            .iter()
            .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte)))
    }
}

impl TryFrom<&Asn1Enumerated> for i64 {
    type Error = Asn1Error;

    /// 轉成有號值；超出範圍回傳 [`Asn1Error::LengthOverflow`]。
    /// 變動時間：依內容長度、符號與數值範圍分支。
    fn try_from(value: &Asn1Enumerated) -> Result<Self, Self::Error> {
        if value.value.len() > 8 {
            return Err(Asn1Error::LengthOverflow);
        }
        let sign = if value.value[0] & 0x80 != 0 { 0xFF } else { 0 };
        let mut bytes = [sign; 8];
        bytes[8 - value.value.len()..].copy_from_slice(&value.value);
        Ok(Self::from_be_bytes(bytes))
    }
}

impl DecodeInner for Asn1Enumerated {
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

impl Decode for Asn1Enumerated {}
impl Tagged for Asn1Enumerated {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Enumerated {
    /// 驗證內容非空且沒有多餘符號位元組，與 INTEGER 共用規則。
    /// 變動時間：依內容長度與符號位元組分支。
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl EncodeContent for Asn1Enumerated {
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

impl EncodeTagged for Asn1Enumerated {}

impl Encode for Asn1Enumerated {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
