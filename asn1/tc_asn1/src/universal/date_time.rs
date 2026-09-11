//! `UTCTime` 與 `GeneralizedTime` 共用的部分：拆開的欄位、範圍檢查、
//! `MMDDhhmmss` 的讀寫、ISO 8601 的顯示。年份的位數和範圍由兩個型別各自管。

use core::fmt;

use crate::error::Asn1Error;

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
    /// 月 1–12、日 1–31、時 0–23、分秒 0–59。年份的範圍由呼叫端先驗過。
    /// 不做日曆驗證（2 月 30 日會過）—— 憑證只拿它比大小。
    pub(crate) fn checked(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, Asn1Error> {
        let in_range = (1..=12).contains(&month)
            && (1..=31).contains(&day)
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
