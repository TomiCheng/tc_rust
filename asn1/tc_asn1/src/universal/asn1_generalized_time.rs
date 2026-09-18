//! ASN.1 `GeneralizedTime`: a time string with a four-digit year.
//!
//! Only `YYYYMMDDhhmmssZ` is accepted. X.690 §11.7 lets DER carry non-zero
//! fractional seconds, but RFC 5280 §4.1.2.5.2 forbids them in certificates, so
//! fractions are rejected too. UTC offsets and omitted seconds are rejected for
//! the same reason as in [`Asn1UtcTime`](super::Asn1UtcTime).

use core::fmt;

use super::date_time::{DateTime, digits, two_digits};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

/// Length of `YYYYMMDDhhmmssZ`.
const LEN: usize = 15;

/// Four-digit year, any of 0-9999. RFC 5280 requires it from 2050 on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1GeneralizedTime(DateTime);

impl Asn1GeneralizedTime {
    pub const TAG: &'static [u8] = super::tag::GENERALIZED_TIME;

    /// Year 0-9999; the other fields follow `DateTime::checked`.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        if year > 9999 {
            return Err(Asn1Error::MalformedValue);
        }
        DateTime::checked(year, month, day, hour, minute, second).map(Self)
    }

    pub fn year(&self) -> u16 {
        self.0.year
    }
    pub fn month(&self) -> u8 {
        self.0.month
    }
    pub fn day(&self) -> u8 {
        self.0.day
    }
    pub fn hour(&self) -> u8 {
        self.0.hour
    }
    pub fn minute(&self) -> u8 {
        self.0.minute
    }
    pub fn second(&self) -> u8 {
        self.0.second
    }
}

impl fmt::Display for Asn1GeneralizedTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl DecodeInner for Asn1GeneralizedTime {
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

impl Decode for Asn1GeneralizedTime {}

impl DecodeContent for Asn1GeneralizedTime {
    /// Accepts `YYYYMMDDhhmmssZ` only. Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let [body @ .., b'Z'] = value else {
            return Err(Asn1Error::MalformedValue);
        };
        if body.len() != LEN - 1 {
            return Err(Asn1Error::MalformedValue);
        }
        let (year, fields) = body.split_at(4);
        let [hi, lo] = year.as_chunks::<2>().0 else {
            return Err(Asn1Error::MalformedValue);
        };
        let year = u16::from(two_digits(hi)?) * 100 + u16::from(two_digits(lo)?);
        DateTime::from_fields(year, fields).map(Self)
    }
}

impl EncodeContent for Asn1GeneralizedTime {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        LEN
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out: &mut [u8; LEN] = out
            .get_mut(..LEN)
            .and_then(|out| out.try_into().ok())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out[0..2].copy_from_slice(&digits((self.0.year / 100) as u8));
        out[2..4].copy_from_slice(&digits((self.0.year % 100) as u8));
        self.0
            .write_fields((&mut out[4..14]).try_into().expect("ten octets"));
        out[14] = b'Z';
        Ok(LEN)
    }
}

impl EncodeTagged for Asn1GeneralizedTime {}

impl Encode for Asn1GeneralizedTime {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
