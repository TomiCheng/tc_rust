//! ASN.1 `OBJECT IDENTIFIER`。

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::DecodingContext;
use crate::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

/// 存 DER 內容。子識別碼的最短編碼是 BER 也要求的，所以位元組就是正規形式，
/// 比對直接比位元組。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1Oid {
    bytes: Vec<u8>,
}

impl Asn1Oid {
    /// Universal identifier octets for this type's default encoding form.
    pub const TAG: &'static [u8] = super::tag::OBJECT_IDENTIFIER;

    /// 由已編好的內容建立；驗證每個子識別碼都最短且完整。
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        if bytes.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut at_start = true;
        let mut value: u64 = 0;
        for byte in bytes {
            // 子識別碼開頭是 0x80 表示前導零（X.690 8.19.2）。
            if at_start && *byte == 0x80 {
                return Err(Asn1Error::MalformedValue);
            }
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add(u64::from(byte & 0x7F)))
                .ok_or(Asn1Error::LengthOverflow)?;
            at_start = byte & 0x80 == 0;
            if at_start {
                value = 0;
            }
        }
        if !at_start {
            return Err(Asn1Error::MalformedValue); // 最後一個子識別碼沒結束
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// 由弧建立，例如 `[1, 2, 840, 113549, 1, 1, 1]`。
    ///
    /// 前兩個弧合併成一個子識別碼：第一個只能是 0、1、2，前兩種情況第二個小於 40。
    pub fn from_arcs(arcs: &[u64]) -> Result<Self, Asn1Error> {
        let [first, second, rest @ ..] = arcs else {
            return Err(Asn1Error::MalformedValue);
        };
        if *first > 2 || (*first < 2 && *second >= 40) {
            return Err(Asn1Error::MalformedValue);
        }
        let head = first
            .checked_mul(40)
            .and_then(|v| v.checked_add(*second))
            .ok_or(Asn1Error::LengthOverflow)?;

        let mut bytes = Vec::new();
        push_base128(&mut bytes, head);
        for arc in rest {
            push_base128(&mut bytes, *arc);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 弧，第一個子識別碼拆回兩個。
    pub fn arcs(&self) -> Arcs<'_> {
        Arcs {
            rest: &self.bytes,
            pending: None,
            first: true,
        }
    }
}

/// 每個位元組帶 7 位，最高位為 1 表示還有下一個；最短形式。
fn push_base128(out: &mut Vec<u8>, value: u64) {
    let bits = 64 - value.leading_zeros();
    let count = bits.div_ceil(7).max(1) as usize;
    for index in 0..count {
        let shift = 7 * (count - 1 - index);
        let more = if index + 1 < count { 0x80 } else { 0 };
        out.push(((value >> shift) & 0x7F) as u8 | more);
    }
}

pub struct Arcs<'a> {
    rest: &'a [u8],
    /// 第一個子識別碼拆開後，等著回的第二個弧。
    pending: Option<u64>,
    first: bool,
}

impl Iterator for Arcs<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if let Some(second) = self.pending.take() {
            return Some(second);
        }
        if self.rest.is_empty() {
            return None;
        }
        // 內容在建構時驗過，所以這裡不會溢位也一定會遇到結束位元組。
        let mut value: u64 = 0;
        let mut consumed = 0;
        for byte in self.rest {
            consumed += 1;
            value = (value << 7) | u64::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                break;
            }
        }
        let is_first = self.first;
        self.first = false;
        self.rest = &self.rest[consumed..];

        if is_first {
            // 40 * a + b：a 是 0、1 時 b < 40；a 是 2 時 b 不受限。
            let (first, second) = match value {
                0..=39 => (0, value),
                40..=79 => (1, value - 40),
                _ => (2, value - 80),
            };
            self.pending = Some(second);
            Some(first)
        } else {
            Some(value)
        }
    }
}

impl fmt::Display for Asn1Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, arc) in self.arcs().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl FromStr for Asn1Oid {
    type Err = Asn1Error;

    /// 點分十進位，例如 `"1.2.840.113549.1.1.1"`。
    fn from_str(s: &str) -> Result<Self, Asn1Error> {
        let mut arcs = Vec::new();
        for part in s.split('.') {
            // 空段、非數字、超過 u64 都是壞輸入。
            let arc = part.parse::<u64>().map_err(|_| Asn1Error::MalformedValue)?;
            arcs.push(arc);
        }
        Self::from_arcs(&arcs)
    }
}

impl<'a> crate::DecodeInner<'a> for Asn1Oid {
    fn decode_inner(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value = <Self as crate::DecodeContent<'a>>::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
    fn decode_inner_der(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value =
            <Self as crate::DecodeContent<'a>>::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}
impl<'a> crate::Decode<'a> for Asn1Oid {
    fn decode(
        buff: &'a [u8],
        options: &crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        <Self as crate::DecodeInner<'a>>::decode_inner(
            buff,
            &mut crate::DecodingContext::new(options),
        )
    }
}

impl<'a> DecodeContent<'a> for Asn1Oid {
    fn decode_content(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }

    fn decode_content_der(
        value: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<Self, crate::Asn1Error> {
        crate::decoding::decode_der_content::<Self>(value, context)
    }
}

impl crate::EncodeContent for Asn1Oid {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.bytes.len()
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

impl crate::EncodeTagged for Asn1Oid {}

impl Encode for Asn1Oid {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecodingOptions;
    use crate::EncodingType;
    use crate::traits::Decode;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT.get(), 16 * 1024 * 1024, 65_536);

    /// rsaEncryption：1.2.840.113549.1.1.1
    const RSA: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];

    #[test]
    fn a_real_oid_decodes_to_its_arcs_and_prints_dotted() {
        let (used, oid) = Asn1Oid::decode(RSA, &OPTIONS).unwrap();
        assert_eq!(used, RSA.len());
        assert_eq!(oid.arcs().collect::<Vec<_>>(), [1, 2, 840, 113549, 1, 1, 1]);
        assert_eq!(oid.to_string(), "1.2.840.113549.1.1.1");
    }

    #[test]
    fn arcs_round_trip_through_from_arcs_and_encode() {
        let oid = Asn1Oid::from_arcs(&[1, 2, 840, 113549, 1, 1, 1]).unwrap();
        let mut out = [0_u8; 16];
        let written = oid
            .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], RSA);
    }

    #[test]
    fn the_first_two_arcs_share_one_subidentifier() {
        // 2.999 → 2*40 + 999 = 1079 → 88 37
        let oid = Asn1Oid::from_arcs(&[2, 999]).unwrap();
        assert_eq!(oid.as_bytes(), &[0x88, 0x37]);
        assert_eq!(oid.arcs().collect::<Vec<_>>(), [2, 999]);

        assert_eq!(Asn1Oid::from_arcs(&[0, 39]).unwrap().as_bytes(), &[39]);
        assert_eq!(Asn1Oid::from_arcs(&[1, 0]).unwrap().as_bytes(), &[40]);
    }

    #[test]
    fn invalid_arc_combinations_are_rejected() {
        assert!(Asn1Oid::from_arcs(&[1]).is_err(), "至少兩個弧");
        assert!(Asn1Oid::from_arcs(&[3, 0]).is_err(), "第一個弧只能是 0 1 2");
        assert!(
            Asn1Oid::from_arcs(&[0, 40]).is_err(),
            "第一個是 0 時第二個要 < 40"
        );
        assert!(Asn1Oid::from_arcs(&[1, 40]).is_err());
        assert!(Asn1Oid::from_arcs(&[2, 40]).is_ok(), "第一個是 2 時不受限");
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        assert!(Asn1Oid::from_der_bytes(&[]).is_err(), "空的");
        assert!(
            Asn1Oid::from_der_bytes(&[0x2A, 0x80, 0x01]).is_err(),
            "子識別碼前導零"
        );
        assert!(
            Asn1Oid::from_der_bytes(&[0x2A, 0x86]).is_err(),
            "最後一個子識別碼沒結束"
        );
        assert!(
            Asn1Oid::from_der_bytes(&[
                0x2A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
            ])
            .is_err(),
            "超過 u64"
        );
    }

    #[test]
    fn a_dotted_string_parses_and_prints_back_the_same() {
        let oid: Asn1Oid = "1.2.840.113549.1.1.1".parse().unwrap();
        let mut out = [0_u8; 16];
        let written = oid
            .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], RSA);
        assert_eq!(oid.to_string(), "1.2.840.113549.1.1.1");
    }

    #[test]
    fn bad_dotted_strings_are_rejected() {
        for s in [
            "",
            "1",
            "1.",
            ".1.2",
            "1..2",
            "1.2.x",
            "3.1",
            "1.40",
            "1.2.99999999999999999999",
        ] {
            assert!(s.parse::<Asn1Oid>().is_err(), "{s:?}");
        }
    }

    #[test]
    fn oids_compare_by_bytes() {
        let a = Asn1Oid::from_arcs(&[1, 2, 840]).unwrap();
        let b = Asn1Oid::from_der_bytes(&[0x2A, 0x86, 0x48]).unwrap();
        assert_eq!(a, b);
        assert!(a < Asn1Oid::from_arcs(&[1, 3]).unwrap());
    }
}
