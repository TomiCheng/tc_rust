//! `UTCTime` 與 `GeneralizedTime` 共用的部分：拆開的欄位、範圍檢查、
//! `MMDDhhmmss` 的讀寫、ISO 8601 的顯示。年份的位數和範圍由兩個型別各自管。

use core::fmt;

use crate::error::Asn1Error;

/// 格里曆閏年：四年一閏、百年不閏、四百年再閏。
pub(crate) fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// 該月天數；呼叫端已確認 month 在 1–12。
pub(crate) fn days_in_month(leap: bool, month: u8) -> u8 {
    match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// 欄位順序就是時間順序，所以 `Ord` 直接是先後。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct DateTime {
    pub(crate) year: u16,
    pub(crate) month: u8,
    pub(crate) day: u8,
    pub(crate) hour: u8,
    pub(crate) minute: u8,
    pub(crate) second: u8,
}

impl DateTime {
    /// 驗證格里曆日期，月 1–12、時 0–23、分秒 0–59。年份範圍由呼叫端先驗過。
    /// 不處理閏秒，秒仍是 0–59。變動時間：分支只依日期與時間欄位。
    pub(crate) fn checked(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        let in_range = (1..=12).contains(&month)
            && (1..=days_in_month(is_leap_year(year), month)).contains(&day)
            && hour <= 23
            && minute <= 59
            && second <= 59;
        if !in_range {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    /// 由年份和 `MMDDhhmmss` 十個位元組建立。
    pub(crate) fn from_fields(year: u16, fields: &[u8]) -> Result<Self, Asn1Error> {
        let [m, d, h, mi, s] = fields.as_chunks::<2>().0 else {
            return Err(Asn1Error::MalformedValue);
        };
        Self::checked(
            year,
            two_digits(m)?,
            two_digits(d)?,
            two_digits(h)?,
            two_digits(mi)?,
            two_digits(s)?,
        )
    }

    /// 把 `MMDDhhmmss` 寫進十個位元組。
    pub(crate) fn write_fields(&self, out: &mut [u8; 10]) {
        for (slot, n) in out.as_chunks_mut::<2>().0.iter_mut().zip([
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        ]) {
            *slot = digits(n);
        }
    }
}

/// 兩個 ASCII 數字 → 數值。
pub(crate) fn two_digits(pair: &[u8; 2]) -> Result<u8, Asn1Error> {
    match pair {
        [a, b] if a.is_ascii_digit() && b.is_ascii_digit() => Ok((a - b'0') * 10 + (b - b'0')),
        _ => Err(Asn1Error::MalformedValue),
    }
}

/// 數值 → 兩個 ASCII 數字。呼叫端保證 `n < 100`。
pub(crate) fn digits(n: u8) -> [u8; 2] {
    [b'0' + n / 10, b'0' + n % 10]
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{Asn1Error, Asn1GeneralizedTime, Asn1UtcTime, DecodeContent, Depth};

    #[test]
    fn utc_times_validate_calendar_dates_after_expanding_two_digit_years() {
        for (wire, year, month, day, valid) in [
            (b"240229000000Z", 2024, 2, 29, true),
            (b"230229000000Z", 2023, 2, 29, false),
            (b"000229000000Z", 2000, 2, 29, true),
            (b"240230000000Z", 2024, 2, 30, false),
            (b"240431000000Z", 2024, 4, 31, false),
            (b"240631000000Z", 2024, 6, 31, false),
            (b"240931000000Z", 2024, 9, 31, false),
            (b"241131000000Z", 2024, 11, 31, false),
            (b"240131000000Z", 2024, 1, 31, true),
            (b"240331000000Z", 2024, 3, 31, true),
            (b"241231000000Z", 2024, 12, 31, true),
        ] {
            let decoded = Asn1UtcTime::try_decode_content(wire, Depth::DEFAULT);
            let built = Asn1UtcTime::new(year, month, day, 0, 0, 0);
            if valid {
                let value = decoded.unwrap();
                assert_eq!(
                    (value.year(), value.month(), value.day()),
                    (year, month, day)
                );
                assert_eq!(built, Ok(value));
            } else {
                assert_eq!(decoded, Err(Asn1Error::MalformedValue), "{wire:?}");
                assert_eq!(built, Err(Asn1Error::MalformedValue));
            }
        }
    }

    #[test]
    fn generalized_times_validate_month_lengths_and_gregorian_century_exceptions() {
        for (wire, year, month, day, valid) in [
            (b"19000229000000Z", 1900, 2, 29, false),
            (b"20000229000000Z", 2000, 2, 29, true),
            (b"20240229000000Z", 2024, 2, 29, true),
            (b"20230229000000Z", 2023, 2, 29, false),
            (b"20240230000000Z", 2024, 2, 30, false),
            (b"20240431000000Z", 2024, 4, 31, false),
            (b"20240631000000Z", 2024, 6, 31, false),
            (b"20240931000000Z", 2024, 9, 31, false),
            (b"20241131000000Z", 2024, 11, 31, false),
            (b"20240131000000Z", 2024, 1, 31, true),
            (b"20240331000000Z", 2024, 3, 31, true),
            (b"20241231000000Z", 2024, 12, 31, true),
        ] {
            let decoded = Asn1GeneralizedTime::try_decode_content(wire, Depth::DEFAULT);
            let built = Asn1GeneralizedTime::new(year, month, day, 0, 0, 0);
            if valid {
                let value = decoded.unwrap();
                assert_eq!(
                    (value.year(), value.month(), value.day()),
                    (year, month, day)
                );
                assert_eq!(built, Ok(value));
            } else {
                assert_eq!(decoded, Err(Asn1Error::MalformedValue), "{wire:?}");
                assert_eq!(built, Err(Asn1Error::MalformedValue));
            }
        }
    }
}
