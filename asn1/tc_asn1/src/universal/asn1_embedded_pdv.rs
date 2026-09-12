//! X.680 §36、§44 的開放資料容器，使用 AUTOMATIC TAGS 的關聯型別。
//!
//! `identification` 是 CHOICE，因此外面的 `[0]` 是 EXPLICIT；各選項與其內部
//! 欄位才是 IMPLICIT。兩個容器都禁止 data-value-descriptor。
//! 本層只驗證線路結構；識別的語法是否適用、OSI context 是否存在由上層判斷。

use super::{Asn1Integer, Asn1Oid, tag};
use crate::traits::{len_octets, write_len};
use crate::{Asn1Error, Asn1Ref, Children, DecodeContent, Depth, Encode, EncodingType};
use alloc::vec::Vec;

/// 識別抽象語法與傳輸語法的六種方式。
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Oid, PdvIdentification};
/// let identification = PdvIdentification::TransferSyntax(
///     Asn1Oid::from_arcs(&[2, 1, 1]).unwrap());
/// assert!(matches!(identification, PdvIdentification::TransferSyntax(_)));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PdvIdentification {
    /// 分別指定抽象語法與傳輸語法。
    Syntaxes {
        abstract_syntax: Asn1Oid,
        transfer_syntax: Asn1Oid,
    },
    /// 單一識別碼同時指定兩種語法。
    Syntax(Asn1Oid),
    /// 已協商的 OSI presentation context。
    PresentationContextId(Asn1Integer),
    /// 協商中的 context，另指定傳輸語法。
    ContextNegotiation {
        presentation_context_id: Asn1Integer,
        transfer_syntax: Asn1Oid,
    },
    /// 抽象語法由應用固定，只指定傳輸語法。
    TransferSyntax(Asn1Oid),
    /// 兩種語法都由應用固定。
    Fixed,
}

fn two_fields(value: &[u8], depth: Depth) -> Result<(Asn1Ref<'_>, Asn1Ref<'_>), Asn1Error> {
    let mut fields = Children::new(value, depth);
    let first = fields.next().ok_or(Asn1Error::Truncated)??;
    let second = fields.next().ok_or(Asn1Error::Truncated)??;
    if let Some(extra) = fields.next() {
        extra?;
        return Err(Asn1Error::TrailingData);
    }
    Ok((first, second))
}

impl PdvIdentification {
    fn decode(field: Asn1Ref<'_>, depth: Depth) -> Result<Self, Asn1Error> {
        Ok(match field.tag() {
            [0xA0] | [0xA3] => {
                let (first, second) = two_fields(field.value(), depth.descend()?)?;
                if first.tag() != [0x80] || second.tag() != [0x81] {
                    return Err(Asn1Error::UnexpectedTag);
                }
                let transfer_syntax = Asn1Oid::from_der_bytes(second.value())?;
                if field.tag() == [0xA0] {
                    Self::Syntaxes {
                        abstract_syntax: Asn1Oid::from_der_bytes(first.value())?,
                        transfer_syntax,
                    }
                } else {
                    Self::ContextNegotiation {
                        presentation_context_id: Asn1Integer::from_der_bytes(first.value())?,
                        transfer_syntax,
                    }
                }
            }
            [0x81] => Self::Syntax(Asn1Oid::from_der_bytes(field.value())?),
            [0x82] => Self::PresentationContextId(Asn1Integer::from_der_bytes(field.value())?),
            [0x84] => Self::TransferSyntax(Asn1Oid::from_der_bytes(field.value())?),
            [0x85] if field.value().is_empty() => Self::Fixed,
            [0x85] => return Err(Asn1Error::MalformedValue),
            _ => return Err(Asn1Error::UnexpectedTag),
        })
    }
}
impl Encode for PdvIdentification {
    fn tag(&self) -> &[u8] {
        match self {
            Self::Syntaxes { .. } => &[0xA0],
            Self::Syntax(_) => &[0x81],
            Self::PresentationContextId(_) => &[0x82],
            Self::ContextNegotiation { .. } => &[0xA3],
            Self::TransferSyntax(_) => &[0x84],
            Self::Fixed => &[0x85],
        }
    }
    /// 變動時間：依選項及內容結構計算。
    fn content_len(&self, rules: EncodingType) -> usize {
        match self {
            Self::Syntaxes {
                abstract_syntax,
                transfer_syntax,
            } => abstract_syntax.encoded_len(rules) + transfer_syntax.encoded_len(rules),
            Self::ContextNegotiation {
                presentation_context_id,
                transfer_syntax,
            } => presentation_context_id.encoded_len(rules) + transfer_syntax.encoded_len(rules),
            Self::Syntax(oid) | Self::TransferSyntax(oid) => oid.content_len(rules),
            Self::PresentationContextId(id) => id.content_len(rules),
            Self::Fixed => 0,
        }
    }
    /// 變動時間：依選項寫入 IMPLICIT 內容。
    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Syntaxes {
                abstract_syntax,
                transfer_syntax,
            } => {
                let at = abstract_syntax.encode_tagged(&[0x80], rules, out)?;
                Ok(at + transfer_syntax.encode_tagged(&[0x81], rules, &mut out[at..])?)
            }
            Self::ContextNegotiation {
                presentation_context_id,
                transfer_syntax,
            } => {
                let at = presentation_context_id.encode_tagged(&[0x80], rules, out)?;
                Ok(at + transfer_syntax.encode_tagged(&[0x81], rules, &mut out[at..])?)
            }
            Self::Syntax(oid) | Self::TransferSyntax(oid) => oid.encode_content(rules, out),
            Self::PresentationContextId(id) => id.encode_content(rules, out),
            Self::Fixed => Ok(0),
        }
    }
}

macro_rules! container {
    ($name:ident, $tag:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            identification: PdvIdentification,
            value: Vec<u8>,
        }
        impl $name {
            /// 接收識別方式與資料的所有權；不解讀被包裝的傳輸語法。
            pub fn new(identification: PdvIdentification, value: Vec<u8>) -> Self {
                Self {
                    identification,
                    value,
                }
            }
            /// 借用識別方式。
            pub fn identification(&self) -> &PdvIdentification {
                &self.identification
            }
            /// 借用資料位元組；不保證它是 UTF-8 或 ASN.1。
            pub fn as_bytes(&self) -> &[u8] {
                &self.value
            }
        }
        impl<'a> DecodeContent<'a> for $name {
            const TAG: &'static [u8] = tag::$tag;
            /// 變動時間：檢查欄位標記與巢狀結構，再複製資料。
            fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
                let depth = depth.descend()?;
                let (identification, data) = two_fields(value, depth)?;
                if identification.tag() != [0xA0] || data.tag() != [0x82] {
                    return Err(Asn1Error::UnexpectedTag);
                }
                let inner_depth = depth.descend()?;
                let inner = Asn1Ref::parse(identification.value(), inner_depth)?;
                if inner.total_len() != identification.value().len() {
                    return Err(Asn1Error::TrailingData);
                }
                Ok(Self::new(
                    PdvIdentification::decode(inner, inner_depth)?,
                    data.value().to_vec(),
                ))
            }
        }
        impl Encode for $name {
            fn tag(&self) -> &[u8] {
                tag::$tag
            }
            /// 變動時間：依識別選項與資料長度計算。
            fn content_len(&self, rules: EncodingType) -> usize {
                let id_len = self.identification.encoded_len(rules);
                1 + len_octets(id_len)
                    + id_len
                    + 1
                    + len_octets(self.value.len())
                    + self.value.len()
            }
            /// 變動時間：寫入 EXPLICIT 識別選項與 IMPLICIT OCTET STRING。
            fn encode_content(
                &self,
                rules: EncodingType,
                out: &mut [u8],
            ) -> Result<usize, Asn1Error> {
                out[0] = 0xA0;
                let mut at = 1 + write_len(self.identification.encoded_len(rules), &mut out[1..]);
                at += self.identification.encode(rules, &mut out[at..])?;
                out[at] = 0x82;
                at += 1;
                at += write_len(self.value.len(), &mut out[at..]);
                out[at..at + self.value.len()].copy_from_slice(&self.value);
                Ok(at + self.value.len())
            }
        }
    };
}
container!(
    Asn1EmbeddedPdv,
    EMBEDDED_PDV,
    "嵌入的 presentation data value；語法識別與資料一起擁有。

# Examples

```
use tc_asn1::{Asn1EmbeddedPdv, PdvIdentification};
let pdv = Asn1EmbeddedPdv::new(PdvIdentification::Fixed, vec![1, 2]);
assert_eq!(pdv.as_bytes(), &[1, 2]);
```"
);
container!(
    Asn1CharacterString,
    CHARACTER_STRING,
    "不限字集的 CHARACTER STRING；線路資料依指定的傳輸語法解讀。

# Examples

```
use tc_asn1::{Asn1CharacterString, PdvIdentification};
let value = Asn1CharacterString::new(PdvIdentification::Fixed, vec![0xff]);
assert_eq!(value.as_bytes(), &[0xff]); // 不假設 UTF-8
```"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decode;
    use alloc::vec;
    #[test]
    fn all_identification_choices_match_automatic_tagging_and_round_trip() {
        let oid = Asn1Oid::from_arcs(&[1, 2]).unwrap();
        let cases = [
            (
                PdvIdentification::Syntaxes {
                    abstract_syntax: oid.clone(),
                    transfer_syntax: oid.clone(),
                },
                vec![0xA0, 6, 0x80, 1, 42, 0x81, 1, 42],
            ),
            (PdvIdentification::Syntax(oid.clone()), vec![0x81, 1, 42]),
            (
                PdvIdentification::PresentationContextId(1i64.into()),
                vec![0x82, 1, 1],
            ),
            (
                PdvIdentification::ContextNegotiation {
                    presentation_context_id: 1i64.into(),
                    transfer_syntax: oid.clone(),
                },
                vec![0xA3, 6, 0x80, 1, 1, 0x81, 1, 42],
            ),
            (PdvIdentification::TransferSyntax(oid), vec![0x84, 1, 42]),
            (PdvIdentification::Fixed, vec![0x85, 0]),
        ];
        for (id, encoded) in cases {
            for rules in [EncodingType::Ber, EncodingType::Der] {
                let value = Asn1EmbeddedPdv::new(id.clone(), vec![0xFF]);
                let mut expected = vec![0x2B, (encoded.len() + 5) as u8, 0xA0, encoded.len() as u8];
                expected.extend_from_slice(&encoded);
                expected.extend_from_slice(&[0x82, 1, 0xFF]);
                let mut out = vec![0; value.encoded_len(rules)];
                assert_eq!(value.encode(rules, &mut out), Ok(expected.len()));
                assert_eq!(out, expected);
                assert_eq!(
                    Asn1EmbeddedPdv::try_decode(&out, Depth::DEFAULT).unwrap().1,
                    value
                );
                out[0] = 0x3D;
                assert_eq!(
                    Asn1CharacterString::try_decode(&out, Depth::DEFAULT)
                        .unwrap()
                        .1,
                    Asn1CharacterString::new(id.clone(), vec![0xFF])
                );
            }
        }
    }
    #[test]
    fn forbidden_descriptors_extra_fields_and_invalid_choices_are_rejected() {
        for bytes in [
            &[0xA0, 2, 0x85, 0, 0x81, 0][..],
            &[0xA0, 2, 0x85, 0, 0x81, 0, 0x82, 0],
            &[0xA0, 2, 0x86, 0, 0x82, 0],
            &[0xA0, 3, 0x85, 1, 0, 0x82, 0],
            &[0xA0, 4, 0x85, 0, 0x85, 0, 0x82, 0],
            &[0xA0, 5, 0xA0, 3, 0x80, 1, 42, 0x82, 0],
            &[0xA0, 2, 0x85, 0],
        ] {
            assert!(Asn1EmbeddedPdv::try_decode_content(bytes, Depth::DEFAULT).is_err());
            assert!(Asn1CharacterString::try_decode_content(bytes, Depth::DEFAULT).is_err());
        }
    }
    #[test]
    fn each_constructed_identification_layer_consumes_depth() {
        let bytes = [
            0x2B, 12, 0xA0, 8, 0xA0, 6, 0x80, 1, 42, 0x81, 1, 42, 0x82, 0,
        ];
        assert_eq!(
            Asn1EmbeddedPdv::try_decode(&bytes, Depth::new(2)),
            Err(Asn1Error::DepthExceeded)
        );
        assert!(Asn1EmbeddedPdv::try_decode(&bytes, Depth::new(3)).is_ok());
    }
}
