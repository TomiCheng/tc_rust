//! ASN.1 `EXTERNAL`：OSI 時代用來包「另一個抽象語法的值」的容器。
//!
//! ```text
//! EXTERNAL ::= [UNIVERSAL 8] IMPLICIT SEQUENCE {
//!     direct-reference       OBJECT IDENTIFIER OPTIONAL,
//!     indirect-reference     INTEGER OPTIONAL,
//!     data-value-descriptor  ObjectDescriptor OPTIONAL,
//!     encoding CHOICE {
//!         single-ASN1-type  [0] ABSTRACT-SYNTAX.&Type,   -- EXPLICIT：型別任意，要保留 tag
//!         octet-aligned     [1] IMPLICIT OCTET STRING,
//!         arbitrary         [2] IMPLICIT BIT STRING
//!     }
//! }
//! ```
//!
//! 這個通用型別的內容照 SEQUENCE 編，
//! tag 換成 `28`。PKIX 用不到，照 bc 補齊。

use alloc::boxed::Box;

use super::tag::{EXTERNAL as TAG, INTEGER, OBJECT_DESCRIPTOR, OBJECT_IDENTIFIER};
use super::{Asn1BitString, Asn1Integer, Asn1ObjectDescriptor, Asn1OctetString, Asn1Oid};
use crate::asn1_any::Asn1Any;
use crate::asn1_ref::{Asn1Ref, Children};
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecode, TryDecodeContent};

const SINGLE_ASN1_TYPE: &[u8] = &[0xA0]; // [0] EXPLICIT，constructed
const OCTET_ALIGNED: &[u8] = &[0x81]; // [1] IMPLICIT，primitive
const ARBITRARY: &[u8] = &[0x82]; // [2] IMPLICIT，primitive

/// `encoding` 那個 CHOICE。三支的標記方式不同：`[0]` 裡是任意型別所以 EXPLICIT
/// （保留內層的 tag），`[1]` `[2]` 型別已知所以 IMPLICIT。
pub enum ExternalEncoding {
    /// `[0]` EXPLICIT：任何值。解進來是 [`Asn1Any`]；造的時候給一個能編碼的值。
    SingleAsn1Type(Box<dyn Encode>),
    /// `[1]` IMPLICIT OCTET STRING。
    OctetAligned(Asn1OctetString),
    /// `[2]` IMPLICIT BIT STRING。
    Arbitrary(Asn1BitString),
}

impl core::fmt::Debug for ExternalEncoding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SingleAsn1Type(_) => f.write_str("SingleAsn1Type(..)"),
            Self::OctetAligned(s) => f.debug_tuple("OctetAligned").field(s).finish(),
            Self::Arbitrary(b) => f.debug_tuple("Arbitrary").field(b).finish(),
        }
    }
}

#[derive(Debug)]
pub struct Asn1External {
    direct_reference: Option<Asn1Oid>,
    indirect_reference: Option<Asn1Integer>,
    data_value_descriptor: Option<Asn1ObjectDescriptor>,
    encoding: ExternalEncoding,
}

impl Asn1External {
    pub fn new(
        direct_reference: Option<Asn1Oid>,
        indirect_reference: Option<Asn1Integer>,
        data_value_descriptor: Option<Asn1ObjectDescriptor>,
        encoding: ExternalEncoding,
    ) -> Self {
        Self {
            direct_reference,
            indirect_reference,
            data_value_descriptor,
            encoding,
        }
    }

    pub fn direct_reference(&self) -> Option<&Asn1Oid> {
        self.direct_reference.as_ref()
    }
    pub fn indirect_reference(&self) -> Option<&Asn1Integer> {
        self.indirect_reference.as_ref()
    }
    pub fn data_value_descriptor(&self) -> Option<&Asn1ObjectDescriptor> {
        self.data_value_descriptor.as_ref()
    }
    pub fn encoding(&self) -> &ExternalEncoding {
        &self.encoding
    }
}

impl<'a> TryDecodeContent<'a> for Asn1External {
    const TAG: &'static [u8] = TAG;

    /// 變動時間：分支只依編碼結構。
    ///
    /// 三個 OPTIONAL 靠 tag 分（照 bc 的做法逐個試），最後一個必須是 `[0]`、`[1]`
    /// 或 `[2]`。
    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        let mut fields = Children::new(value, depth);
        let mut next = fields.next().ok_or(Asn1Error::Truncated)??;

        // 三個 OPTIONAL：是就吃掉、往下看一個；不是就留給下一個判斷。
        let mut take =
            |expected: &[u8], next: &mut Asn1Ref<'a>| -> Result<Option<Asn1Ref<'a>>, Asn1Error> {
                if next.tag() != expected {
                    return Ok(None);
                }
                let taken = *next;
                *next = fields.next().ok_or(Asn1Error::Truncated)??;
                Ok(Some(taken))
            };
        let direct_reference = take(OBJECT_IDENTIFIER, &mut next)?
            .map(|f| f.decode_as::<Asn1Oid>(depth))
            .transpose()?;
        let indirect_reference = take(INTEGER, &mut next)?
            .map(|f| f.decode_as::<Asn1Integer>(depth))
            .transpose()?;
        let data_value_descriptor = take(OBJECT_DESCRIPTOR, &mut next)?
            .map(|f| f.decode_as::<Asn1ObjectDescriptor>(depth))
            .transpose()?;

        let encoding = match next.tag() {
            SINGLE_ASN1_TYPE => {
                // EXPLICIT：[0] 裡剛好一個完整的 TLV。
                let (used, inner) = Asn1Any::try_decode(next.value(), depth)?;
                if used != next.value().len() {
                    return Err(Asn1Error::TrailingData);
                }
                ExternalEncoding::SingleAsn1Type(Box::new(inner))
            }
            OCTET_ALIGNED => ExternalEncoding::OctetAligned(Asn1OctetString::try_decode_content(
                next.value(),
                depth,
            )?),
            ARBITRARY => {
                ExternalEncoding::Arbitrary(Asn1BitString::try_decode_content(next.value(), depth)?)
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };

        if fields.next().is_some() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(Self {
            direct_reference,
            indirect_reference,
            data_value_descriptor,
            encoding,
        })
    }
}

impl ExternalEncoding {
    fn encoded_len(&self, rules: EncodingType) -> usize {
        match self {
            // EXPLICIT：外層 [0] 的內容是內層的完整 TLV。
            Self::SingleAsn1Type(inner) => {
                let inner_len = inner.encoded_len(rules);
                SINGLE_ASN1_TYPE.len() + crate::traits::len_octets(inner_len) + inner_len
            }
            Self::OctetAligned(s) => s.encoded_len_tagged(OCTET_ALIGNED, rules),
            Self::Arbitrary(b) => b.encoded_len_tagged(ARBITRARY, rules),
        }
    }

    fn encode(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::SingleAsn1Type(inner) => {
                let inner_len = inner.encoded_len(rules);
                out[..1].copy_from_slice(SINGLE_ASN1_TYPE);
                let mut at = 1 + crate::traits::write_len(inner_len, &mut out[1..]);
                at += inner.encode(rules, &mut out[at..])?;
                Ok(at)
            }
            Self::OctetAligned(s) => s.encode_tagged(OCTET_ALIGNED, rules, out),
            Self::Arbitrary(b) => b.encode_tagged(ARBITRARY, rules, out),
        }
    }
}

impl Encode for Asn1External {
    fn tag(&self) -> &[u8] {
        TAG
    }

    fn content_len(&self, rules: EncodingType) -> usize {
        self.direct_reference
            .as_ref()
            .map_or(0, |v| v.encoded_len(rules))
            + self
                .indirect_reference
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self
                .data_value_descriptor
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self.encoding.encoded_len(rules)
    }

    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.direct_reference {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.indirect_reference {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.data_value_descriptor {
            at += v.encode(rules, &mut out[at..])?;
        }
        at += self.encoding.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    const DEPTH: Depth = Depth::DEFAULT;

    fn encode(e: &Asn1External) -> Vec<u8> {
        let mut out = alloc::vec![0_u8; e.encoded_len(EncodingType::Der)];
        e.encode(EncodingType::Der, &mut out).unwrap();
        out
    }

    #[test]
    fn octet_aligned_with_a_direct_reference_round_trips() {
        // 28 08  06 02 2A 03  81 02 41 42
        let input = [0x28, 0x08, 0x06, 0x02, 0x2A, 0x03, 0x81, 0x02, 0x41, 0x42];
        let (used, e) = Asn1External::try_decode(&input, DEPTH).unwrap();

        assert_eq!(used, input.len());
        assert_eq!(e.direct_reference().unwrap().to_string(), "1.2.3");
        assert!(e.indirect_reference().is_none());
        assert!(matches!(e.encoding(), ExternalEncoding::OctetAligned(s) if s.as_bytes() == b"AB"));
        assert_eq!(encode(&e), input);
    }

    #[test]
    fn single_asn1_type_is_explicit_and_keeps_the_inner_tag() {
        // 28 09  06 02 2A 03  A0 03 02 01 05     ← [0] 裡是 INTEGER 5，tag 02 保留
        let input = [
            0x28, 0x09, 0x06, 0x02, 0x2A, 0x03, 0xA0, 0x03, 0x02, 0x01, 0x05,
        ];
        let (_, e) = Asn1External::try_decode(&input, DEPTH).unwrap();

        let ExternalEncoding::SingleAsn1Type(inner) = e.encoding() else {
            panic!("應該是 [0]");
        };
        assert_eq!(inner.tag(), &[0x02]);
        assert_eq!(encode(&e), input);
    }

    #[test]
    fn all_three_optionals_are_told_apart_by_tag() {
        // 06 02 2A 03  02 01 07  07 01 78  82 02 00 A0
        let input = [
            0x28, 0x0E, 0x06, 0x02, 0x2A, 0x03, 0x02, 0x01, 0x07, 0x07, 0x01, 0x78, 0x82, 0x02,
            0x00, 0xA0,
        ];
        let (_, e) = Asn1External::try_decode(&input, DEPTH).unwrap();

        assert_eq!(e.direct_reference().unwrap().to_string(), "1.2.3");
        assert_eq!(u8::try_from(e.indirect_reference().unwrap()), Ok(7));
        assert_eq!(e.data_value_descriptor().unwrap().as_bytes(), b"x");
        assert!(matches!(e.encoding(), ExternalEncoding::Arbitrary(b) if b.as_bytes() == [0xA0]));
        assert_eq!(encode(&e), input);
    }

    #[test]
    fn a_built_value_encodes_with_the_external_tag() {
        let e = Asn1External::new(
            None,
            Some(Asn1Integer::from(7_u8)),
            None,
            ExternalEncoding::SingleAsn1Type(Box::new(Asn1Integer::from(5_u8))),
        );
        assert_eq!(
            encode(&e),
            [0x28, 0x08, 0x02, 0x01, 0x07, 0xA0, 0x03, 0x02, 0x01, 0x05]
        );
    }

    #[test]
    fn the_encoding_is_mandatory_and_must_be_one_of_the_three() {
        assert_eq!(
            Asn1External::try_decode(&[0x28, 0x04, 0x06, 0x02, 0x2A, 0x03], DEPTH).err(),
            Some(Asn1Error::Truncated),
            "只有 OPTIONAL，沒有 encoding"
        );
        assert_eq!(
            Asn1External::try_decode(&[0x28, 0x02, 0x83, 0x00], DEPTH).err(),
            Some(Asn1Error::UnexpectedTag),
            "[3] 不存在"
        );
        assert_eq!(
            Asn1External::try_decode(
                &[0x28, 0x07, 0xA0, 0x05, 0x02, 0x01, 0x05, 0x05, 0x00],
                DEPTH
            )
            .err(),
            Some(Asn1Error::TrailingData),
            "[0] 裡只能有一個值"
        );
    }
}
