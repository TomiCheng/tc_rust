//! ASN.1 `UTCTime`：兩位數年份的時間字串。
//!
//! 只接受 DER 形式 `YYMMDDhhmmssZ`（X.690 11.8：必須有秒、必須是 `Z`）。BER 允許的
//! 省略秒和時區偏移**刻意不接受** —— RFC 5280 強制 DER 形式，憑證裡不會出現
//! 別的，接受偏移就得做時區換算，為不會發生的情況付整套代價。這是解碼寬鬆
//! 照 BER 這條原則的例外，理由如上。

use core::fmt;

use super::date_time::{DateTime, digits, two_digits};
use super::tag::UTC_TIME as TAG;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

/// DER 形式的長度：`YYMMDDhhmmssZ`。
const LEN: usize = 13;

/// 年份已照 RFC 5280 §4.1.2.5.1 補成四位：`YY >= 50` 是 19YY，否則 20YY。
/// 所以能表示的範圍是 1950–2049，之後要用 [`Asn1GeneralizedTime`]。
///
/// [`Asn1GeneralizedTime`]: super::Asn1GeneralizedTime
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1UtcTime(DateTime);

impl Asn1UtcTime {
    /// 年 1950–2049，其餘欄位的範圍見 `DateTime::checked`。
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

impl<'a> TryDecodeContent<'a> for Asn1UtcTime {
    const TAG: &'static [u8] = TAG;

    /// 變動時間：分支只依編碼結構。只接受 `YYMMDDhhmmssZ`。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        let [yy @ .., b'Z'] = value else {
            return Err(Asn1Error::MalformedValue);
        };
        if yy.len() != LEN - 1 {
            return Err(Asn1Error::MalformedValue);
        }
        let (year, fields) = yy.split_at(2);
        let yy = two_digits(year.try_into().map_err(|_| Asn1Error::MalformedValue)?)?;
        let year = if yy >= 50 { 1900 } else { 2000 } + u16::from(yy);
        Self::new_from(DateTime::from_fields(year, fields)?)
    }
}

impl Asn1UtcTime {
    fn new_from(inner: DateTime) -> Result<Self, Asn1Error> {
        Self::new(
            inner.year,
            inner.month,
            inner.day,
            inner.hour,
            inner.minute,
            inner.second,
        )
    }
}

impl Encode for Asn1UtcTime {
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, _: EncodingType) -> usize {
        LEN
    }
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[0..2].copy_from_slice(&digits((self.0.year % 100) as u8));
        self.0
            .write_fields((&mut out[2..12]).try_into().expect("十個位元組"));
        out[12] = b'Z';
        Ok(LEN)
    }
}

impl fmt::Display for Asn1UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TryDecode;
    use alloc::string::ToString;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn a_der_utc_time_decodes_and_prints_as_iso_8601() {
        let input = b"\x17\x0D240911123000Z";
        let (used, t) = Asn1UtcTime::try_decode(input, DEPTH).unwrap();
        assert_eq!(used, 15);
        assert_eq!(t.to_string(), "2024-09-11T12:30:00Z");
        assert_eq!(t, Asn1UtcTime::new(2024, 9, 11, 12, 30, 0).unwrap());
    }

    #[test]
    fn the_century_flips_at_fifty() {
        assert_eq!(
            Asn1UtcTime::try_decode_content(b"500101000000Z", DEPTH)
                .unwrap()
                .year(),
            1950
        );
        assert_eq!(
            Asn1UtcTime::try_decode_content(b"991231235959Z", DEPTH)
                .unwrap()
                .year(),
            1999
        );
        assert_eq!(
            Asn1UtcTime::try_decode_content(b"000101000000Z", DEPTH)
                .unwrap()
                .year(),
            2000
        );
        assert_eq!(
            Asn1UtcTime::try_decode_content(b"491231235959Z", DEPTH)
                .unwrap()
                .year(),
            2049
        );
    }

    #[test]
    fn ber_variants_are_deliberately_rejected() {
        assert!(
            Asn1UtcTime::try_decode_content(b"2409111230Z", DEPTH).is_err(),
            "沒有秒"
        );
        assert!(
            Asn1UtcTime::try_decode_content(b"240911123000+0800", DEPTH).is_err(),
            "時區偏移"
        );
        assert!(
            Asn1UtcTime::try_decode_content(b"240911123000", DEPTH).is_err(),
            "沒有 Z"
        );
    }

    #[test]
    fn out_of_range_fields_are_rejected() {
        assert!(
            Asn1UtcTime::try_decode_content(b"241311123000Z", DEPTH).is_err(),
            "13 月"
        );
        assert!(
            Asn1UtcTime::try_decode_content(b"240900123000Z", DEPTH).is_err(),
            "0 日"
        );
        assert!(
            Asn1UtcTime::try_decode_content(b"240911243000Z", DEPTH).is_err(),
            "24 時"
        );
        assert!(
            Asn1UtcTime::try_decode_content(b"240911126000Z", DEPTH).is_err(),
            "60 分"
        );
        assert!(
            Asn1UtcTime::try_decode_content(b"24091112300AZ", DEPTH).is_err(),
            "非數字"
        );
        assert!(
            Asn1UtcTime::new(2050, 1, 1, 0, 0, 0).is_err(),
            "超過 2049 要用 GeneralizedTime"
        );
    }

    #[test]
    fn times_order_chronologically() {
        let earlier = Asn1UtcTime::new(1999, 12, 31, 23, 59, 59).unwrap();
        let later = Asn1UtcTime::new(2000, 1, 1, 0, 0, 0).unwrap();
        assert!(earlier < later);
    }

    #[test]
    fn encode_and_decode_round_trip() {
        let t = Asn1UtcTime::new(2049, 12, 31, 23, 59, 59).unwrap();
        let mut out = [0_u8; 16];
        let written = t.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], b"\x17\x0D491231235959Z");

        let (_, back) = Asn1UtcTime::try_decode(&out[..written], DEPTH).unwrap();
        assert_eq!(back, t);
    }
}
