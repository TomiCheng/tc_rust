//! ASN.1 `GeneralizedTime`：四位數年份的時間字串。
//!
//! 只接受 `YYYYMMDDhhmmssZ`。X.690 11.7 的 DER 允許非零的小數秒，但 RFC 5280
//! §4.1.2.5.2 明文禁止憑證使用小數秒，所以這裡連小數秒也拒絕。時區偏移和
//! 省略秒同 [`Asn1UtcTime`] 的理由不接受。
//!
//! [`Asn1UtcTime`]: super::Asn1UtcTime

use core::fmt;

use super::date_time::{DateTime, digits, two_digits};
use crate::decoding_options::DecodingOptions;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

/// `YYYYMMDDhhmmssZ`。
const LEN: usize = 15;

/// 四位年份，任何 0–9999 都能表示。RFC 5280 規定 2050 年起要用它。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1GeneralizedTime(DateTime);

impl Asn1GeneralizedTime {
    /// Universal identifier octets for this type's default encoding form.
    pub const TAG: &'static [u8] = super::tag::GENERALIZED_TIME;

    /// 年 0–9999，其餘欄位的範圍見 `DateTime::checked`。
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

impl<'a> crate::Decode<'a> for Asn1GeneralizedTime {
    fn try_decode(
        buff: &'a [u8],
        options: crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, options)?;
        if element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value =
            <Self as crate::DecodeContent<'a>>::try_decode_content(element.value(), options)?;
        Ok((element.total_len(), value))
    }
}

impl<'a> DecodeContent<'a> for Asn1GeneralizedTime {
    /// 變動時間：分支只依編碼結構。只接受 `YYYYMMDDhhmmssZ`。
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
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

impl crate::EncodeContent for Asn1GeneralizedTime {
    fn content_len(&self, _: EncodingOptions) -> usize {
        LEN
    }

    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        out[0..2].copy_from_slice(&digits((self.0.year / 100) as u8));
        out[2..4].copy_from_slice(&digits((self.0.year % 100) as u8));
        self.0
            .write_fields((&mut out[4..14]).try_into().expect("十個位元組"));
        out[14] = b'Z';
        Ok(LEN)
    }
}

impl crate::EncodeTagged for Asn1GeneralizedTime {}

impl Encode for Asn1GeneralizedTime {
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

impl fmt::Display for Asn1GeneralizedTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Decode;
    use alloc::string::ToString;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn a_der_generalized_time_decodes_and_prints_as_iso_8601() {
        let input = b"\x18\x0F20500101000000Z";
        let (used, t) = Asn1GeneralizedTime::try_decode(input, OPTIONS).unwrap();
        assert_eq!(used, 17);
        assert_eq!(t.to_string(), "2050-01-01T00:00:00Z");
        assert_eq!(t, Asn1GeneralizedTime::new(2050, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn four_digit_years_have_no_century_rule() {
        assert_eq!(
            Asn1GeneralizedTime::try_decode_content(b"19500101000000Z", OPTIONS)
                .unwrap()
                .year(),
            1950
        );
        assert_eq!(
            Asn1GeneralizedTime::try_decode_content(b"99991231235959Z", OPTIONS)
                .unwrap()
                .year(),
            9999
        );
        assert!(
            Asn1GeneralizedTime::new(2050, 1, 1, 0, 0, 0).is_ok(),
            "UTCTime 到不了的年份"
        );
    }

    #[test]
    fn fractional_seconds_and_ber_variants_are_rejected() {
        assert!(
            Asn1GeneralizedTime::try_decode_content(b"20240911123000.5Z", OPTIONS).is_err(),
            "小數秒，RFC 5280 禁止"
        );
        assert!(
            Asn1GeneralizedTime::try_decode_content(b"202409111230Z", OPTIONS).is_err(),
            "沒有秒"
        );
        assert!(
            Asn1GeneralizedTime::try_decode_content(b"20240911123000+0800", OPTIONS).is_err(),
            "時區偏移"
        );
        assert!(
            Asn1GeneralizedTime::try_decode_content(b"20240911123000", OPTIONS).is_err(),
            "沒有 Z"
        );
        assert!(
            Asn1GeneralizedTime::try_decode_content(b"240911123000Z", OPTIONS).is_err(),
            "兩位年是 UTCTime 的事"
        );
    }

    #[test]
    fn encode_and_decode_round_trip() {
        let t = Asn1GeneralizedTime::new(2099, 12, 31, 23, 59, 59).unwrap();
        let mut out = [0_u8; 20];
        let written = t.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..written], b"\x18\x0F20991231235959Z");

        let (_, back) = Asn1GeneralizedTime::try_decode(&out[..written], OPTIONS).unwrap();
        assert_eq!(back, t);
    }
}
