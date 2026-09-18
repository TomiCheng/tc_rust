//! ASN.1 `UTCTime`: a time string with a two-digit year.
//!
//! Only the DER form `YYMMDDhhmmssZ` is accepted (X.690 §11.8: seconds present,
//! `Z` only). The BER options of omitting the seconds or using a UTC offset are
//! **deliberately rejected**: RFC 5280 mandates the DER form, certificates never
//! carry anything else, and accepting offsets would mean time-zone arithmetic
//! for a case that does not occur. This is the one exception to lenient BER
//! decoding, for that reason.

use core::fmt;

use super::date_time::{DateTime, digits, two_digits};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, DecodingOptions, Encode,
    EncodeContent, EncodeTagged, EncodingOptions,
};

/// Length of the DER form `YYMMDDhhmmssZ`.
const LEN: usize = 13;

/// The year is expanded per RFC 5280 §4.1.2.5.1: `YY >= 50` is 19YY, otherwise
/// 20YY, so the representable range is 1950-2049. Later dates need
/// [`Asn1GeneralizedTime`](super::Asn1GeneralizedTime).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1UtcTime(DateTime);

impl Asn1UtcTime {
    pub const TAG: &'static [u8] = super::tag::UTC_TIME;

    /// Year 1950-2049; the other fields follow `DateTime::checked`.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        if !(1950..=2049).contains(&year) {
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

impl fmt::Display for Asn1UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl DecodeInner for Asn1UtcTime {
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

impl Decode for Asn1UtcTime {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl DecodeContent for Asn1UtcTime {
    /// Accepts `YYMMDDhhmmssZ` only. Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let [yy @ .., b'Z'] = value else {
            return Err(Asn1Error::MalformedValue);
        };
        if yy.len() != LEN - 1 {
            return Err(Asn1Error::MalformedValue);
        }
        let (year, fields) = yy.split_at(2);
        let yy = two_digits(year.try_into().map_err(|_| Asn1Error::MalformedValue)?)?;
        let year = if yy >= 50 { 1900 } else { 2000 } + u16::from(yy);
        let inner = DateTime::from_fields(year, fields)?;
        Self::new(
            inner.year,
            inner.month,
            inner.day,
            inner.hour,
            inner.minute,
            inner.second,
        )
    }

    fn decode_content_der(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        // decode_content already accepts nothing but the DER form.
        Self::decode_content(value, context)
    }
}

impl EncodeContent for Asn1UtcTime {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        LEN
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out: &mut [u8; LEN] = out
            .get_mut(..LEN)
            .and_then(|out| out.try_into().ok())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out[0..2].copy_from_slice(&digits((self.0.year % 100) as u8));
        self.0
            .write_fields((&mut out[2..12]).try_into().expect("ten octets"));
        out[12] = b'Z';
        Ok(LEN)
    }
}

impl EncodeTagged for Asn1UtcTime {}

impl Encode for Asn1UtcTime {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
