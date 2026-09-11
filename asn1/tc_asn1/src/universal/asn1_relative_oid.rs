//! ASN.1 `RELATIVE-OID`，每個弧各自使用最短 base-128 編碼。

use super::tag::RELATIVE_OID as TAG;
use crate::{Asn1Error, Depth, Encode, EncodingType, TryDecodeContent};
use alloc::vec::Vec;
use core::{fmt, str::FromStr};

/// 相對物件識別碼。起始節點由上層提供，不合併前兩個弧。
/// 與目前的 OBJECT IDENTIFIER API 一致，每個弧限制為 `u64`。
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1RelativeOid, Encode, EncodingType};
/// let value: Asn1RelativeOid = "4.3.128".parse().unwrap();
/// let mut out = [0; 6];
/// value.encode(EncodingType::Der, &mut out).unwrap();
/// assert_eq!(out, [0x0D, 4, 4, 3, 0x81, 0]);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1RelativeOid {
    bytes: Vec<u8>,
}

impl Asn1RelativeOid {
    /// 驗證非空、每個弧完整且最短。變動時間：依內容長度與弧分支。
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        if bytes.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut start = true;
        let mut value = 0_u64;
        for byte in bytes {
            if start && *byte == 0x80 {
                return Err(Asn1Error::MalformedValue);
            }
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add(u64::from(byte & 0x7F)))
                .ok_or(Asn1Error::LengthOverflow)?;
            start = byte & 0x80 == 0;
            if start {
                value = 0;
            }
        }
        if !start {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// 由至少一個弧建立。變動時間：依弧數與弧的位元長度分支。
    pub fn from_arcs(arcs: &[u64]) -> Result<Self, Asn1Error> {
        if arcs.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut bytes = Vec::new();
        for value in arcs {
            let count = (64 - value.leading_zeros()).div_ceil(7).max(1);
            for i in (0..count).rev() {
                bytes.push(((value >> (7 * i)) & 0x7F) as u8 | if i == 0 { 0 } else { 0x80 });
            }
        }
        Ok(Self { bytes })
    }
    /// 借用編碼內容。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// 走訪各弧。變動時間：每個弧依其編碼長度解讀。
    pub fn arcs(&self) -> impl Iterator<Item = u64> + '_ {
        self.bytes
            .split_inclusive(|byte| byte & 0x80 == 0)
            .map(|bytes| {
                bytes
                    .iter()
                    .fold(0_u64, |n, b| (n << 7) | u64::from(b & 0x7F))
            })
    }
}
impl FromStr for Asn1RelativeOid {
    type Err = Asn1Error;
    /// 點分十進位表示。變動時間：依字串與弧的長度分支。
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let arcs = text
            .split('.')
            .map(|part| {
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Asn1Error::MalformedValue);
                }
                part.parse::<u64>().map_err(|_| Asn1Error::LengthOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_arcs(&arcs)
    }
}
impl fmt::Display for Asn1RelativeOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.arcs().enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}
impl<'a> TryDecodeContent<'a> for Asn1RelativeOid {
    const TAG: &'static [u8] = TAG;
    /// 變動時間：驗證每個弧，不合併開頭的弧。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        Self::from_der_bytes(value)
    }
}
impl Encode for Asn1RelativeOid {
    fn tag(&self) -> &[u8] {
        TAG
    }
    /// 常數時間：已存有內容長度。
    fn content_len(&self, _: EncodingType) -> usize {
        self.bytes.len()
    }
    /// 變動時間：原樣複製已驗證的內容。
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TryDecode;
    #[test]
    fn arcs_are_independent_and_round_trip_through_both_encodings() {
        let value = Asn1RelativeOid::from_arcs(&[4, 3, 128]).unwrap();
        for rules in [EncodingType::Ber, EncodingType::Der] {
            let mut out = [0; 6];
            assert_eq!(value.encode(rules, &mut out), Ok(6));
            assert_eq!(out, [13, 4, 4, 3, 129, 0]);
            assert_eq!(
                Asn1RelativeOid::try_decode(&out, Depth::DEFAULT),
                Ok((6, value.clone()))
            );
        }
        assert_eq!(value.arcs().collect::<Vec<_>>(), [4, 3, 128]);
        assert_eq!("4.3.128".parse::<Asn1RelativeOid>(), Ok(value));
    }
    #[test]
    fn zero_and_the_largest_supported_arc_remain_distinct() {
        let value = Asn1RelativeOid::from_arcs(&[0, u64::MAX]).unwrap();
        assert_eq!(value.arcs().collect::<Vec<_>>(), [0, u64::MAX]);
        assert_eq!(Asn1RelativeOid::from_der_bytes(value.as_bytes()), Ok(value));
    }
    #[test]
    fn empty_truncated_nonminimal_and_overflowing_arcs_are_rejected() {
        for bytes in [&[][..], &[0x80, 0], &[0x81]] {
            assert_eq!(
                Asn1RelativeOid::from_der_bytes(bytes),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            Asn1RelativeOid::from_der_bytes(&[0xFF; 11]),
            Err(Asn1Error::LengthOverflow)
        );
        for text in ["", ".1", "1.", "+1", "1.a"] {
            assert!(text.parse::<Asn1RelativeOid>().is_err());
        }
        assert_eq!(
            Asn1RelativeOid::try_decode(&[6, 1, 0], Depth::DEFAULT),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
