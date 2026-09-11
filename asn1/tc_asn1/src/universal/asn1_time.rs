//! X.680 §38 的 TIME 與四個有用時間型別。
//!
//! 建構函式使用帶分隔符號的值記法，`as_str` 回傳正規化後的記法。
//! X.690 §8.26 規定 DATE／TIME-OF-DAY／DATE-TIME 在線路上去掉分隔符號，
//! DURATION 去掉 `P`；TIME 則保留。BER 與 DER 都輸出 §11.9 的正規形式。
//! 驗證包括 Gregorian 日曆、週次、精度、時差與分量結構；不查詢閏秒公告或
//! 時區資料庫，也不判斷區間端點的先後。秒數 60 的實際適用性由上層判斷。

use super::{tag, time_value};
use crate::{Asn1Error, Depth, Encode, EncodingType, TryDecodeContent};
use alloc::{format, string::String};

#[derive(Clone, Copy)]
enum Kind {
    Time,
    Date,
    Clock,
    DateTime,
    Duration,
}
impl Kind {
    fn validate(self, text: &str) -> Result<String, Asn1Error> {
        match self {
            Self::Time => time_value::time(text),
            Self::Date => time_value::useful_date(text),
            Self::Clock => time_value::useful_clock(text),
            Self::DateTime => time_value::useful_date_time(text),
            Self::Duration => time_value::duration(text),
        }
    }
    fn wire(self, text: &str) -> String {
        match self {
            Self::Time => String::from(text),
            Self::Duration => String::from(&text[1..]),
            _ => text
                .chars()
                .filter(|c| !matches!(c, '-' | ':' | 'T'))
                .collect(),
        }
    }
    fn notation(self, wire: &str) -> Result<String, Asn1Error> {
        if matches!(self, Self::Time) {
            return Ok(String::from(wire));
        }
        if matches!(self, Self::Duration) {
            return Ok(format!("P{wire}"));
        }
        let len = match self {
            Self::Date => 8,
            Self::Clock => 6,
            _ => 14,
        };
        if wire.len() != len || !wire.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(match self {
            Self::Date => format!("{}-{}-{}", &wire[..4], &wire[4..6], &wire[6..]),
            Self::Clock => format!("{}:{}:{}", &wire[..2], &wire[2..4], &wire[4..]),
            _ => format!(
                "{}-{}-{}T{}:{}:{}",
                &wire[..4],
                &wire[4..6],
                &wire[6..8],
                &wire[8..10],
                &wire[10..12],
                &wire[12..]
            ),
        })
    }
}
macro_rules! time_type {
    ($name:ident, $tag:ident, $kind:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            text: String,
            wire: String,
        }
        impl $name {
            /// 驗證值記法並正規化。變動時間：依日期分量、數字與字串長度分支。
            /// 無效的結構或數值回傳 [`Asn1Error::MalformedValue`]。
            pub fn new(text: &str) -> Result<Self, Asn1Error> {
                let text = Kind::$kind.validate(text)?;
                let wire = Kind::$kind.wire(&text);
                Ok(Self { text, wire })
            }
            /// 借用含分隔符號的正規值記法；不是完整 TLV。
            pub fn as_str(&self) -> &str {
                &self.text
            }
        }
        impl<'a> TryDecodeContent<'a> for $name {
            const TAG: &'static [u8] = tag::$tag;
            /// 變動時間：從線路格式還原值記法，驗證並正規化。
            fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
                let wire = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
                Self::new(&Kind::$kind.notation(wire)?)
            }
        }
        impl Encode for $name {
            fn tag(&self) -> &[u8] {
                tag::$tag
            }
            /// 常數時間：讀取已準備的線路內容長度。
            fn content_len(&self, _: EncodingType) -> usize {
                self.wire.len()
            }
            /// 變動時間：複製正規化後的線路內容。
            fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
                out[..self.wire.len()].copy_from_slice(self.wire.as_bytes());
                Ok(self.wire.len())
            }
        }
    };
}
time_type!(
    Asn1Time,
    TIME,
    Time,
    r#"TIME：日期、時間、區間、持續時間或重複區間。

相等性比較正規記法，保留精度、時區與日期表示方式；不做跨時區換算。
驗證日曆及分量結構，不查詢閏秒公告或判斷區間端點先後。

# Examples

```
use tc_asn1::Asn1Time;
let interval = Asn1Time::new("R3/2024-01-01T12:30+08:00/2024-01-02T12:30+08").unwrap();
assert_eq!(interval.as_str(), "R3/2024-01-01T12:30+08/2024-01-02T12:30");
```"#
);
time_type!(
    Asn1Date,
    DATE,
    Date,
    r#"DATE：1582–9999 年的 Gregorian 日期，記法為 `YYYY-MM-DD`。

# Examples

```
use tc_asn1::{Asn1Date, Encode, EncodingType};
let date = Asn1Date::new("2024-02-29").unwrap();
let mut out = [0; 11];
date.encode(EncodingType::Der, &mut out).unwrap();
assert_eq!(&out[..3], &[0x1f, 0x1f, 8]);
assert_eq!(&out[3..], b"20240229");
assert!(Asn1Date::new("2023-02-29").is_err());
```"#
);
time_type!(
    Asn1TimeOfDay,
    TIME_OF_DAY,
    Clock,
    r#"TIME-OF-DAY：不帶時區或小數的 `hh:mm:ss`，允許日末午夜 `24:00:00`。

# Examples

```
use tc_asn1::Asn1TimeOfDay;
assert!(Asn1TimeOfDay::new("24:00:00").is_ok());
assert!(Asn1TimeOfDay::new("24:00:01").is_err());
assert!(Asn1TimeOfDay::new("12:00:00Z").is_err());
```"#
);
time_type!(
    Asn1DateTime,
    DATE_TIME,
    DateTime,
    r#"DATE-TIME：`YYYY-MM-DDThh:mm:ss`，年份 1582–9999，不帶時區或小數。

# Examples

```
use tc_asn1::Asn1DateTime;
let value = Asn1DateTime::new("2024-02-29T24:00:00").unwrap();
assert_eq!(value.as_str(), "2024-02-29T24:00:00");
assert!(Asn1DateTime::new("2024-02-30T12:00:00").is_err());
```"#
);
time_type!(
    Asn1Duration,
    DURATION,
    Duration,
    r#"DURATION：`P` 開頭的持續時間，不將月換算為固定天數。

最後一個分量代表精度，零值仍保留；其他零分量依 DER 規則省略。

# Examples

```
use tc_asn1::Asn1Duration;
let duration = Asn1Duration::new("P0Y2M0DT0,00S").unwrap();
assert_eq!(duration.as_str(), "P2MT0.00S");
assert_ne!(duration, Asn1Duration::new("P2M").unwrap());
```"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TryDecode;
    #[test]
    fn useful_time_types_write_the_standard_separator_free_contents() {
        type Case = (alloc::boxed::Box<dyn Encode>, &'static [u8], &'static [u8]);
        let cases: [Case; 4] = [
            (
                alloc::boxed::Box::new(Asn1Date::new("2024-02-29").unwrap()),
                tag::DATE,
                b"20240229",
            ),
            (
                alloc::boxed::Box::new(Asn1TimeOfDay::new("23:59:60").unwrap()),
                tag::TIME_OF_DAY,
                b"235960",
            ),
            (
                alloc::boxed::Box::new(Asn1DateTime::new("2024-02-29T24:00:00").unwrap()),
                tag::DATE_TIME,
                b"20240229240000",
            ),
            (
                alloc::boxed::Box::new(Asn1Duration::new("P1Y0MT2H0S").unwrap()),
                tag::DURATION,
                b"1YT2H0S",
            ),
        ];
        for (value, tag, content) in cases {
            for rules in [EncodingType::Ber, EncodingType::Der] {
                let mut out = alloc::vec![0; value.encoded_len(rules)];
                assert_eq!(value.encode(rules, &mut out), Ok(out.len()));
                assert_eq!(&out[..2], tag);
                assert_eq!(out[2] as usize, content.len());
                assert_eq!(&out[3..], content);
            }
        }
        assert_eq!(
            Asn1Date::try_decode(
                &[
                    0x1f, 0x1f, 8, b'2', b'0', b'2', b'4', b'0', b'2', b'2', b'9'
                ],
                Depth::DEFAULT
            )
            .unwrap()
            .1
            .as_str(),
            "2024-02-29"
        );
    }
    #[test]
    fn all_time_types_decode_and_reencode_their_canonical_contents() {
        macro_rules! check {
            ($ty:ident, $text:literal) => {
                let value = $ty::new($text).unwrap();
                let mut out = alloc::vec![0; value.encoded_len(EncodingType::Der)];
                value.encode(EncodingType::Der, &mut out).unwrap();
                assert_eq!($ty::try_decode(&out, Depth::DEFAULT).unwrap().1, value);
                if out[0] == 0x1F { out[1] = 0x25; } else { out[0] = 0x04; }
                assert_eq!($ty::try_decode(&out, Depth::DEFAULT), Err(Asn1Error::UnexpectedTag));
                assert!($ty::try_decode_content(&[], Depth::DEFAULT).is_err());
                assert!($ty::try_decode_content(&[0xff], Depth::DEFAULT).is_err());
            }
        }
        check!(Asn1Time, "R/P1W");
        check!(Asn1Date, "1582-01-01");
        check!(Asn1TimeOfDay, "00:00:00");
        check!(Asn1DateTime, "9999-12-31T23:59:59");
        check!(Asn1Duration, "PT0.000S");
        assert!(Asn1Date::try_decode_content(b"2024-02-29", Depth::DEFAULT).is_err());
        assert!(Asn1Duration::try_decode_content(b"P1D", Depth::DEFAULT).is_err());
    }
    #[test]
    fn gregorian_dates_ordinal_dates_and_iso_weeks_obey_calendar_boundaries() {
        for text in [
            "2000-02-29",
            "2024-366",
            "2020-W53-7",
            "0000-02-29",
            "-0004-02-29",
            "+12000-02-29",
            "19C",
            "-01C",
            "+123C",
            "2024-12",
            "2024-W01",
        ] {
            assert!(Asn1Time::new(text).is_ok(), "{text}");
        }
        for text in [
            "1900-02-29",
            "2023-366",
            "2021-W53",
            "2024-W00",
            "2024-W01-0",
            "2024-04-31",
            "2024-00-01",
            "2024-13-01",
            "2024-01-00",
            "-0000",
            "+2024",
            "+01234",
            "2024-000",
        ] {
            assert!(Asn1Time::new(text).is_err(), "{text}");
        }
        assert!(Asn1Date::new("1581-12-31").is_err());
        assert!(Asn1DateTime::new("1581-12-31T00:00:00").is_err());
    }
    #[test]
    fn time_precision_midnight_and_offsets_are_checked_without_losing_fraction_digits() {
        for (input, expected) in [
            ("12,00+08:00", "12.00+08"),
            ("24:00:00.000Z", "24:00:00.000Z"),
            ("23:59:60-15", "23:59:60-15"),
            ("12:30+00:30", "12:30+00:30"),
        ] {
            assert_eq!(Asn1Time::new(input).unwrap().as_str(), expected);
        }
        for text in [
            "25",
            "24.1",
            "24:01",
            "12:60",
            "12:00:61",
            "12+15:01",
            "12-00",
            "12-00:00",
            "12+16",
            "12:00Zx",
            "12.",
            "12.2:30",
            "2024T12:00",
            "2024-02T12:00",
        ] {
            assert!(Asn1Time::new(text).is_err(), "{text}");
        }
        assert!(Asn1TimeOfDay::new("12:00:00.0").is_err());
    }
    #[test]
    fn durations_normalize_zero_components_but_preserve_the_last_component_and_precision() {
        for (input, expected) in [
            ("P0Y0M0D", "P0D"),
            ("P1Y0DT0H0M0.00S", "P1YT0.00S"),
            ("P0,50W", "P0.50W"),
            (
                "PT123456789012345678901234567890S",
                "PT123456789012345678901234567890S",
            ),
        ] {
            assert_eq!(Asn1Duration::new(input).unwrap().as_str(), expected);
        }
        for input in [
            "", "P", "PT", "P1DT", "P1W1D", "P1WT1H", "P1M1Y", "P01D", "P1.2DT1S", "P1D1D", "P-1D",
            "PT1Y", "P1H", "P.5D", "P1.D", "PTT1S",
        ] {
            assert!(Asn1Duration::new(input).is_err(), "{input}");
        }
    }
    #[test]
    fn intervals_require_matching_endpoint_properties_and_canonicalize_repeated_offsets() {
        for text in [
            "2024-01-01/2024-12-31",
            "2024-01-01/P1Y",
            "P1Y/2024-12-31",
            "R5/P1D",
            "R/12:00/13:00",
            "-0002/-0001",
        ] {
            assert!(Asn1Time::new(text).is_ok(), "{text}");
        }
        assert_eq!(
            Asn1Time::new("R3/12:00+08:00/13:00+08").unwrap().as_str(),
            "R3/12:00+08/13:00"
        );
        for text in [
            "2024/2025-01",
            "12:00/13",
            "12.0/13.00",
            "12Z/13",
            "12/13Z",
            "R/2024",
            "R01/P1D",
            "P1D/P2D",
            "2024/2025/2026",
            "1581/1582",
            "00:00/24:00",
        ] {
            assert!(Asn1Time::new(text).is_err(), "{text}");
        }
    }
    #[test]
    fn standard_annex_examples_cover_dates_times_durations_and_recurring_intervals() {
        // X.680 (2021) G.3；略去 date-time2 的 +02.00 排字錯誤，以表 7 的 +02:00 為準。
        for text in [
            "1985-04-12",
            "1985-102",
            "1985-W15-5",
            "1985-W15",
            "1985-04",
            "1985",
            "+11985-04-12",
            "-0002-04-12",
            "19C",
            "15:27:46",
            "15:28",
            "15:27:35,5",
            "23:20:30Z",
            "23Z",
            "15:27:46+01:00",
            "15:27:46+01",
            "15:27:46-05:00",
            "1985-04-12T10:15:30",
            "1985-04-01T01:30:00+02:00",
            "1985-102T23:50:30Z",
            "1985-W14-5T23:50:30",
            "1985-04-12T23:20:50/1985-06-25T10:30:00",
            "1985-04-12T12:30:00+02:00/1985-04-12T13:30:00+02:00",
            "1985-04-12T12:30:00+02:00/1985-04-12T13:30:00",
            "1985-04-12/1985-06-25",
            "P2Y10M15DT10H20M30S",
            "P1Y6M",
            "PT72H",
            "1985-04-12T23:20:00/P1Y2M15DT12H",
            "P1Y2M15DT12H/1985-04-12T23:20:00",
            "R15/P2Y10M15DT10H20M30S",
            "R/P2Y15DT10H20M30S",
            "R2/P1Y6M",
            "R/P1Y2M15DT12H/1985-04-12T23:20:50",
        ] {
            let value = Asn1Time::new(text).unwrap();
            assert_eq!(Asn1Time::new(value.as_str()).unwrap(), value);
        }
    }
}
