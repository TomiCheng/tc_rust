//! 沒有結構定義時使用的 ASN.1 值樹；已知值會解讀，未知 universal 編碼保真。
//!
//! 只處理公開資料，不歸零。變動時間操作依編碼結構分支，排序另比較公開內容。
//! 沒有 schema 就無法區分 SET 與 SET OF CHOICE；此樹的 SET 依類別、號碼、
//! 完整編碼排序，不承諾所有 schema 下皆是標準 DER，也不承諾與 bc 遞迴比較
//! 的結果相同。已知是 SET OF 時應使用 [`Asn1SetOf`]。

mod dump;
mod tagged;

pub use tagged::{Asn1Tagged, TaggedContent};

use crate::traits::len_octets;
use crate::universal::*;
use crate::{
    Asn1Any, Asn1Class, Asn1Error, Asn1Ref, Depth, Encode, EncodingType, TryDecode,
    TryDecodeContent,
};
use alloc::vec::Vec;

/// 擁有資料的 ASN.1 樹，供未知結構的檢視與臨時建構使用。
///
/// 已知值重編時會正規化表頭及各型別允許的內容；[`Self::Unknown`] 原樣保留。
/// 驗簽章必須用原位元組，而非重編結果。此型別不歸零，只能放公開資料。
/// SET 採類別、號碼、完整編碼排序；沒有 schema 無法保證 SET OF CHOICE 的 DER。
///
/// # Examples
///
/// 拿到未知結構時，先解成樹看內容，再重編。
///
/// ```
/// use tc_asn1::{Asn1Object, Depth, Encode, EncodingType, TryDecode};
///
/// let input = [0x30, 5, 2, 1, 42, 5, 0];
/// let (used, tree) = Asn1Object::try_decode(&input, Depth::DEFAULT).unwrap();
/// assert_eq!(used, input.len());
/// assert_eq!(tree.to_string(), "SEQUENCE\n  INTEGER 42\n  NULL\n");
/// let mut out = vec![0; tree.encoded_len(EncodingType::Der)];
/// tree.encode(EncodingType::Der, &mut out).unwrap();
/// assert_eq!(out, input);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asn1Object {
    Boolean(Asn1Boolean),
    Integer(Asn1Integer),
    BitString(Asn1BitString),
    OctetString(Asn1OctetString),
    Null,
    Oid(Asn1Oid),
    ObjectDescriptor(Asn1ObjectDescriptor),
    External(Asn1External),
    Real(Asn1Real),
    Enumerated(Asn1Enumerated),
    EmbeddedPdv(Asn1EmbeddedPdv),
    Utf8String(Asn1Utf8String),
    RelativeOid(Asn1RelativeOid),
    Time(Asn1Time),
    Sequence(Vec<Asn1Object>),
    Set(Vec<Asn1Object>),
    NumericString(Asn1NumericString),
    PrintableString(Asn1PrintableString),
    TeletexString(Asn1TeletexString),
    VideotexString(Asn1VideotexString),
    Ia5String(Asn1Ia5String),
    UtcTime(Asn1UtcTime),
    GeneralizedTime(Asn1GeneralizedTime),
    GraphicString(Asn1GraphicString),
    VisibleString(Asn1VisibleString),
    GeneralString(Asn1GeneralString),
    UniversalString(Asn1UniversalString),
    CharacterString(Asn1CharacterString),
    BmpString(Asn1BmpString),
    Date(Asn1Date),
    TimeOfDay(Asn1TimeOfDay),
    DateTime(Asn1DateTime),
    Duration(Asn1Duration),
    OidIri(Asn1OidIri),
    RelativeOidIri(Asn1RelativeOidIri),
    /// 非 universal 類別；constructed 解成子元素，primitive 保留內容。
    Tagged(Asn1Tagged),
    /// 未支援的 universal 編碼，例如 BER constructed 字串或未指派號碼。
    /// dump 遇到超過 `u64` 的號碼時，以 `tag=` 加完整十六進位識別位元組顯示。
    Unknown(Asn1Any),
}

macro_rules! from_leaf {
    ($($variant:ident: $ty:ty),* $(,)?) => {$(
        impl From<$ty> for Asn1Object {
            /// 接收葉節點的所有權。變動時間：分支只依編碼結構。
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    )*};
}
from_leaf! {
    Boolean: Asn1Boolean,
    Integer: Asn1Integer,
    BitString: Asn1BitString,
    OctetString: Asn1OctetString,
    Oid: Asn1Oid,
    ObjectDescriptor: Asn1ObjectDescriptor,
    External: Asn1External,
    Real: Asn1Real,
    Enumerated: Asn1Enumerated,
    EmbeddedPdv: Asn1EmbeddedPdv,
    Utf8String: Asn1Utf8String,
    RelativeOid: Asn1RelativeOid,
    Time: Asn1Time,
    NumericString: Asn1NumericString,
    PrintableString: Asn1PrintableString,
    TeletexString: Asn1TeletexString,
    VideotexString: Asn1VideotexString,
    Ia5String: Asn1Ia5String,
    UtcTime: Asn1UtcTime,
    GeneralizedTime: Asn1GeneralizedTime,
    GraphicString: Asn1GraphicString,
    VisibleString: Asn1VisibleString,
    GeneralString: Asn1GeneralString,
    UniversalString: Asn1UniversalString,
    CharacterString: Asn1CharacterString,
    BmpString: Asn1BmpString,
    Date: Asn1Date,
    TimeOfDay: Asn1TimeOfDay,
    DateTime: Asn1DateTime,
    Duration: Asn1Duration,
    OidIri: Asn1OidIri,
    RelativeOidIri: Asn1RelativeOidIri,
    Tagged: Asn1Tagged,
}
impl From<Asn1Null> for Asn1Object {
    /// 建立 NULL 節點。變動時間：分支只依編碼結構。
    fn from(_: Asn1Null) -> Self {
        Self::Null
    }
}

impl Asn1Object {
    /// 借用 Sequence 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_sequence(&self) -> Option<&[Asn1Object]> {
        match self {
            Self::Sequence(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Set 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_set(&self) -> Option<&[Asn1Object]> {
        match self {
            Self::Set(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Integer 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_integer(&self) -> Option<&Asn1Integer> {
        match self {
            Self::Integer(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Oid 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_oid(&self) -> Option<&Asn1Oid> {
        match self {
            Self::Oid(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 OctetString 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_octet_string(&self) -> Option<&Asn1OctetString> {
        match self {
            Self::OctetString(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 BitString 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_bit_string(&self) -> Option<&Asn1BitString> {
        match self {
            Self::BitString(value) => Some(value),
            _ => None,
        }
    }
    /// 借用 Tagged 節點的內容；其他種類回傳 `None`。常數時間。
    pub fn as_tagged(&self) -> Option<&Asn1Tagged> {
        match self {
            Self::Tagged(value) => Some(value),
            _ => None,
        }
    }

    /// 把借用的元素整棵解開。變動時間：分支只依編碼結構。
    ///
    /// # Examples
    ///
    /// [`Asn1Any`] 保存的原始元素可以另行解讀，原資料仍保留。
    ///
    /// ```
    /// use tc_asn1::{Asn1Any, Asn1Object, Depth, TryDecode};
    ///
    /// let (_, any) = Asn1Any::try_decode(&[2, 1, 7], Depth::DEFAULT).unwrap();
    /// let tree = Asn1Object::from_ref(&any.as_ref(), Depth::DEFAULT).unwrap();
    /// assert_eq!(i64::try_from(tree.as_integer().unwrap()), Ok(7));
    /// assert_eq!(any.raw(), [2, 1, 7]);
    /// ```
    pub fn from_ref(element: &Asn1Ref<'_>, depth: Depth) -> Result<Self, Asn1Error> {
        if element.class() != Asn1Class::Universal {
            return Ok(Self::Tagged(Asn1Tagged::from_ref(element, depth)?));
        }
        Ok(match element.tag() {
            tag::BOOLEAN => Self::Boolean(Asn1Boolean::try_decode_content(element.value(), depth)?),
            tag::INTEGER => Self::Integer(Asn1Integer::try_decode_content(element.value(), depth)?),
            tag::BIT_STRING => {
                Self::BitString(Asn1BitString::try_decode_content(element.value(), depth)?)
            }
            tag::OCTET_STRING => {
                Self::OctetString(Asn1OctetString::try_decode_content(element.value(), depth)?)
            }
            tag::NULL => {
                Asn1Null::try_decode_content(element.value(), depth)?;
                Self::Null
            }
            tag::OBJECT_IDENTIFIER => {
                Self::Oid(Asn1Oid::try_decode_content(element.value(), depth)?)
            }
            tag::OBJECT_DESCRIPTOR => Self::ObjectDescriptor(
                Asn1ObjectDescriptor::try_decode_content(element.value(), depth)?,
            ),
            tag::EXTERNAL => {
                Self::External(Asn1External::try_decode_content(element.value(), depth)?)
            }
            tag::REAL => Self::Real(Asn1Real::try_decode_content(element.value(), depth)?),
            tag::ENUMERATED => {
                Self::Enumerated(Asn1Enumerated::try_decode_content(element.value(), depth)?)
            }
            tag::EMBEDDED_PDV => {
                Self::EmbeddedPdv(Asn1EmbeddedPdv::try_decode_content(element.value(), depth)?)
            }
            tag::UTF8_STRING => {
                Self::Utf8String(Asn1Utf8String::try_decode_content(element.value(), depth)?)
            }
            tag::RELATIVE_OID => {
                Self::RelativeOid(Asn1RelativeOid::try_decode_content(element.value(), depth)?)
            }
            tag::TIME => Self::Time(Asn1Time::try_decode_content(element.value(), depth)?),
            tag::SEQUENCE => Self::Sequence(decode_children(element, depth)?),
            tag::SET => Self::Set(decode_children(element, depth)?),
            tag::NUMERIC_STRING => Self::NumericString(Asn1NumericString::try_decode_content(
                element.value(),
                depth,
            )?),
            tag::PRINTABLE_STRING => Self::PrintableString(
                Asn1PrintableString::try_decode_content(element.value(), depth)?,
            ),
            tag::TELETEX_STRING => Self::TeletexString(Asn1TeletexString::try_decode_content(
                element.value(),
                depth,
            )?),
            tag::VIDEOTEX_STRING => Self::VideotexString(Asn1VideotexString::try_decode_content(
                element.value(),
                depth,
            )?),
            tag::IA5_STRING => {
                Self::Ia5String(Asn1Ia5String::try_decode_content(element.value(), depth)?)
            }
            tag::UTC_TIME => {
                Self::UtcTime(Asn1UtcTime::try_decode_content(element.value(), depth)?)
            }
            tag::GENERALIZED_TIME => Self::GeneralizedTime(
                Asn1GeneralizedTime::try_decode_content(element.value(), depth)?,
            ),
            tag::GRAPHIC_STRING => Self::GraphicString(Asn1GraphicString::try_decode_content(
                element.value(),
                depth,
            )?),
            tag::VISIBLE_STRING => Self::VisibleString(Asn1VisibleString::try_decode_content(
                element.value(),
                depth,
            )?),
            tag::GENERAL_STRING => Self::GeneralString(Asn1GeneralString::try_decode_content(
                element.value(),
                depth,
            )?),
            tag::UNIVERSAL_STRING => Self::UniversalString(
                Asn1UniversalString::try_decode_content(element.value(), depth)?,
            ),
            tag::CHARACTER_STRING => Self::CharacterString(
                Asn1CharacterString::try_decode_content(element.value(), depth)?,
            ),
            tag::BMP_STRING => {
                Self::BmpString(Asn1BmpString::try_decode_content(element.value(), depth)?)
            }
            tag::DATE => Self::Date(Asn1Date::try_decode_content(element.value(), depth)?),
            tag::TIME_OF_DAY => {
                Self::TimeOfDay(Asn1TimeOfDay::try_decode_content(element.value(), depth)?)
            }
            tag::DATE_TIME => {
                Self::DateTime(Asn1DateTime::try_decode_content(element.value(), depth)?)
            }
            tag::DURATION => {
                Self::Duration(Asn1Duration::try_decode_content(element.value(), depth)?)
            }
            tag::OID_IRI => Self::OidIri(Asn1OidIri::try_decode_content(element.value(), depth)?),
            tag::RELATIVE_OID_IRI => Self::RelativeOidIri(Asn1RelativeOidIri::try_decode_content(
                element.value(),
                depth,
            )?),
            _ => Self::Unknown(Asn1Any::from(element)),
        })
    }
}

impl<'a> TryDecode<'a> for Asn1Object {
    /// 解讀第一個完整元素。變動時間：分支只依編碼結構。
    fn try_decode(buff: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, depth)?;
        Ok((element.total_len(), Self::from_ref(&element, depth)?))
    }
}

impl Encode for Asn1Object {
    /// 取得識別位元組。變動時間：分支只依編碼結構，未知節點委派原始元素。
    fn tag(&self) -> &[u8] {
        match self {
            Self::Boolean(_) => tag::BOOLEAN,
            Self::Integer(_) => tag::INTEGER,
            Self::BitString(_) => tag::BIT_STRING,
            Self::OctetString(_) => tag::OCTET_STRING,
            Self::Null => tag::NULL,
            Self::Oid(_) => tag::OBJECT_IDENTIFIER,
            Self::ObjectDescriptor(_) => tag::OBJECT_DESCRIPTOR,
            Self::External(_) => tag::EXTERNAL,
            Self::Real(_) => tag::REAL,
            Self::Enumerated(_) => tag::ENUMERATED,
            Self::EmbeddedPdv(_) => tag::EMBEDDED_PDV,
            Self::Utf8String(_) => tag::UTF8_STRING,
            Self::RelativeOid(_) => tag::RELATIVE_OID,
            Self::Time(_) => tag::TIME,
            Self::Sequence(_) => tag::SEQUENCE,
            Self::Set(_) => tag::SET,
            Self::NumericString(_) => tag::NUMERIC_STRING,
            Self::PrintableString(_) => tag::PRINTABLE_STRING,
            Self::TeletexString(_) => tag::TELETEX_STRING,
            Self::VideotexString(_) => tag::VIDEOTEX_STRING,
            Self::Ia5String(_) => tag::IA5_STRING,
            Self::UtcTime(_) => tag::UTC_TIME,
            Self::GeneralizedTime(_) => tag::GENERALIZED_TIME,
            Self::GraphicString(_) => tag::GRAPHIC_STRING,
            Self::VisibleString(_) => tag::VISIBLE_STRING,
            Self::GeneralString(_) => tag::GENERAL_STRING,
            Self::UniversalString(_) => tag::UNIVERSAL_STRING,
            Self::CharacterString(_) => tag::CHARACTER_STRING,
            Self::BmpString(_) => tag::BMP_STRING,
            Self::Date(_) => tag::DATE,
            Self::TimeOfDay(_) => tag::TIME_OF_DAY,
            Self::DateTime(_) => tag::DATE_TIME,
            Self::Duration(_) => tag::DURATION,
            Self::OidIri(_) => tag::OID_IRI,
            Self::RelativeOidIri(_) => tag::RELATIVE_OID_IRI,
            Self::Tagged(value) => value.tag(),
            Self::Unknown(value) => value.tag(),
        }
    }

    /// 計算內容長度。變動時間：分支只依編碼結構。
    fn content_len(&self, rules: EncodingType) -> usize {
        match self {
            Self::Null => 0,
            Self::Sequence(children) | Self::Set(children) => children_len(children, rules),
            Self::Boolean(value) => value.content_len(rules),
            Self::Integer(value) => value.content_len(rules),
            Self::BitString(value) => value.content_len(rules),
            Self::OctetString(value) => value.content_len(rules),
            Self::Oid(value) => value.content_len(rules),
            Self::ObjectDescriptor(value) => value.content_len(rules),
            Self::External(value) => value.content_len(rules),
            Self::Real(value) => value.content_len(rules),
            Self::Enumerated(value) => value.content_len(rules),
            Self::EmbeddedPdv(value) => value.content_len(rules),
            Self::Utf8String(value) => value.content_len(rules),
            Self::RelativeOid(value) => value.content_len(rules),
            Self::Time(value) => value.content_len(rules),
            Self::NumericString(value) => value.content_len(rules),
            Self::PrintableString(value) => value.content_len(rules),
            Self::TeletexString(value) => value.content_len(rules),
            Self::VideotexString(value) => value.content_len(rules),
            Self::Ia5String(value) => value.content_len(rules),
            Self::UtcTime(value) => value.content_len(rules),
            Self::GeneralizedTime(value) => value.content_len(rules),
            Self::GraphicString(value) => value.content_len(rules),
            Self::VisibleString(value) => value.content_len(rules),
            Self::GeneralString(value) => value.content_len(rules),
            Self::UniversalString(value) => value.content_len(rules),
            Self::CharacterString(value) => value.content_len(rules),
            Self::BmpString(value) => value.content_len(rules),
            Self::Date(value) => value.content_len(rules),
            Self::TimeOfDay(value) => value.content_len(rules),
            Self::DateTime(value) => value.content_len(rules),
            Self::Duration(value) => value.content_len(rules),
            Self::OidIri(value) => value.content_len(rules),
            Self::RelativeOidIri(value) => value.content_len(rules),
            Self::Tagged(value) => value.content_len(rules),
            Self::Unknown(value) => value.content_len(rules),
        }
    }

    /// 寫入內容。變動時間：分支只依編碼結構，SET 排序另比較公開編碼內容。
    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Null => Ok(0),
            Self::Set(children) if rules == EncodingType::Der => {
                let mut encodings = children
                    .iter()
                    .map(|member| Ok((tag_key(member.tag())?, encode_member(member, rules)?)))
                    .collect::<Result<Vec<_>, Asn1Error>>()?;
                encodings.sort();
                copy_encodings(encodings.iter().map(|(_, bytes)| bytes.as_slice()), out)
            }
            Self::Sequence(children) | Self::Set(children) => encode_children(children, rules, out),
            Self::Boolean(value) => value.encode_content(rules, out),
            Self::Integer(value) => value.encode_content(rules, out),
            Self::BitString(value) => value.encode_content(rules, out),
            Self::OctetString(value) => value.encode_content(rules, out),
            Self::Oid(value) => value.encode_content(rules, out),
            Self::ObjectDescriptor(value) => value.encode_content(rules, out),
            Self::External(value) => value.encode_content(rules, out),
            Self::Real(value) => value.encode_content(rules, out),
            Self::Enumerated(value) => value.encode_content(rules, out),
            Self::EmbeddedPdv(value) => value.encode_content(rules, out),
            Self::Utf8String(value) => value.encode_content(rules, out),
            Self::RelativeOid(value) => value.encode_content(rules, out),
            Self::Time(value) => value.encode_content(rules, out),
            Self::NumericString(value) => value.encode_content(rules, out),
            Self::PrintableString(value) => value.encode_content(rules, out),
            Self::TeletexString(value) => value.encode_content(rules, out),
            Self::VideotexString(value) => value.encode_content(rules, out),
            Self::Ia5String(value) => value.encode_content(rules, out),
            Self::UtcTime(value) => value.encode_content(rules, out),
            Self::GeneralizedTime(value) => value.encode_content(rules, out),
            Self::GraphicString(value) => value.encode_content(rules, out),
            Self::VisibleString(value) => value.encode_content(rules, out),
            Self::GeneralString(value) => value.encode_content(rules, out),
            Self::UniversalString(value) => value.encode_content(rules, out),
            Self::CharacterString(value) => value.encode_content(rules, out),
            Self::BmpString(value) => value.encode_content(rules, out),
            Self::Date(value) => value.encode_content(rules, out),
            Self::TimeOfDay(value) => value.encode_content(rules, out),
            Self::DateTime(value) => value.encode_content(rules, out),
            Self::Duration(value) => value.encode_content(rules, out),
            Self::OidIri(value) => value.encode_content(rules, out),
            Self::RelativeOidIri(value) => value.encode_content(rules, out),
            Self::Tagged(value) => value.encode_content(rules, out),
            Self::Unknown(value) => value.encode_content(rules, out),
        }
    }

    /// 計算完整長度；未知元素包含原始表頭。變動時間：分支只依編碼結構。
    fn encoded_len(&self, rules: EncodingType) -> usize {
        if let Self::Unknown(value) = self {
            return value.encoded_len(rules);
        }
        let len = self.content_len(rules);
        self.tag().len() + len_octets(len) + len
    }

    /// 寫出完整元素；未知元素連原始表頭一起複製。變動時間：分支只依編碼結構。
    fn encode(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        if let Self::Unknown(value) = self {
            return value.encode(rules, out);
        }
        self.encode_tagged(self.tag(), rules, out)
    }
}

fn decode_children(element: &Asn1Ref<'_>, depth: Depth) -> Result<Vec<Asn1Object>, Asn1Error> {
    let depth = depth.descend()?;
    element
        .children(depth)
        .map(|child| Asn1Object::from_ref(&child?, depth))
        .collect()
}

fn children_len(children: &[Asn1Object], rules: EncodingType) -> usize {
    children.iter().map(|child| child.encoded_len(rules)).sum()
}

fn encode_children(
    children: &[Asn1Object],
    rules: EncodingType,
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    let mut at = 0;
    for child in children {
        at += child.encode(rules, out.get_mut(at..).ok_or(Asn1Error::BufferTooSmall)?)?;
    }
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, string::ToString, vec};

    fn decode(input: &[u8]) -> Asn1Object {
        let (used, tree) = Asn1Object::try_decode(input, Depth::DEFAULT).unwrap();
        assert_eq!(used, input.len());
        tree
    }

    #[test]
    fn digest_info_decodes_as_a_complete_tree_and_dumps_and_reencodes_exactly() {
        let mut input = vec![
            0x30, 0x31, 0x30, 0x0D, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1, 5, 0, 4, 0x20,
        ];
        input.extend_from_slice(&[0xAB; 32]);
        let tree = decode(&input);
        let expected = Asn1Object::Sequence(vec![
            Asn1Object::Sequence(vec![
                Asn1Object::Oid("2.16.840.1.101.3.4.2.1".parse().unwrap()),
                Asn1Object::Null,
            ]),
            Asn1OctetString::new(&[0xAB; 32]).into(),
        ]);
        assert_eq!(tree, expected);
        assert_eq!(tree.clone(), expected);
        assert_eq!(
            tree.to_string(),
            concat!(
                "SEQUENCE\n  SEQUENCE\n    OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1\n",
                "    NULL\n  OCTET STRING (32 bytes) ",
                "abababababababababababababababababababababababababababababababab\n"
            )
        );
        assert_eq!(encode_member(&tree, EncodingType::Der).unwrap(), input);
        assert_eq!(
            tree.as_sequence().unwrap()[0].as_sequence().unwrap()[0]
                .as_oid()
                .unwrap()
                .to_string(),
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(
            tree.as_sequence().unwrap()[1]
                .as_octet_string()
                .unwrap()
                .as_bytes(),
            &[0xAB; 32]
        );
    }

    #[test]
    fn der_sets_compare_tag_numbers_before_identifier_octets() {
        let tree = Asn1Object::Set(vec![
            Asn1UtcTime::new(2023, 1, 1, 0, 0, 0).unwrap().into(),
            Asn1Object::Sequence(vec![]),
        ]);
        assert_eq!(
            encode_member(&tree, EncodingType::Der).unwrap(),
            b"\x31\x11\x30\x00\x17\x0d230101000000Z"
        );
        let ber = b"\x31\x11\x17\x0d230101000000Z\x30\x00";
        assert_eq!(encode_member(&tree, EncodingType::Ber).unwrap(), ber);
        assert_eq!(decode(ber), tree);
        assert_eq!(tree.as_set().unwrap().len(), 2);
    }

    #[test]
    fn der_sets_compare_full_encodings_when_tags_match_without_changing_stored_order() {
        let tree = Asn1Object::Set(vec![
            Asn1Integer::from(5_u8).into(),
            Asn1Integer::from(3_u8).into(),
        ]);
        assert_eq!(
            encode_member(&tree, EncodingType::Der).unwrap(),
            [0x31, 6, 2, 1, 3, 2, 1, 5]
        );
        let ber = [0x31, 6, 2, 1, 5, 2, 1, 3];
        assert_eq!(encode_member(&tree, EncodingType::Ber).unwrap(), ber);
        assert_eq!(decode(&ber), tree);
    }

    #[test]
    fn unknown_universal_elements_preserve_their_full_encoding_even_under_der() {
        for (input, text) in [
            (
                &b"\x24\x03\x04\x01\xaa"[..],
                "[UNIVERSAL 4] constructed (3 bytes) 0401aa\n",
            ),
            (&b"\x1f\x25\x00"[..], "[UNIVERSAL 37] (0 bytes)\n"),
            (
                &b"\x1f\x25\x81\x01\xaa"[..],
                "[UNIVERSAL 37] (1 bytes) aa\n",
            ),
            (
                &b"\x24\x80\x04\x01\xaa\x00\x00"[..],
                "[UNIVERSAL 4] constructed (3 bytes) 0401aa\n",
            ),
        ] {
            let tree = decode(input);
            assert!(matches!(tree, Asn1Object::Unknown(_)));
            assert_eq!(tree.to_string(), text);
            assert_eq!(tree.encoded_len(EncodingType::Der), input.len());
            assert_eq!(encode_member(&tree, EncodingType::Der).unwrap(), input);
            let nested = Asn1Object::Sequence(vec![tree.clone()]);
            let encoding = encode_member(&nested, EncodingType::Der).unwrap();
            assert_eq!(&encoding[2..], input);
            assert_eq!(decode(&encoding), nested);
        }
    }

    #[test]
    fn known_elements_normalize_ber_headers_and_boolean_contents() {
        let input = [0x30, 0x80, 1, 0x81, 1, 1, 0, 0];
        let tree = decode(&input);
        assert_eq!(tree, Asn1Object::Sequence(vec![Asn1Boolean(true).into()]));
        assert_eq!(
            encode_member(&tree, EncodingType::Der).unwrap(),
            [0x30, 3, 1, 1, 0xff]
        );
    }

    #[test]
    fn each_constructed_level_consumes_exactly_one_unit_of_depth() {
        for input in [
            &b"\x30\x04\x30\x02\x30\x00"[..],
            &b"\xa0\x04\x31\x02\x30\x00"[..],
            &b"\x30\x80\x30\x80\x30\x80\x00\x00\x00\x00\x00\x00"[..],
        ] {
            assert!(Asn1Object::try_decode(input, Depth::new(3)).is_ok());
            assert_eq!(
                Asn1Object::try_decode(input, Depth::new(2)),
                Err(Asn1Error::DepthExceeded)
            );
        }
        assert_eq!(
            Asn1Object::try_decode(b"\x30\x06\x30\x04\x30\x02\x30\x00", Depth::new(3)),
            Err(Asn1Error::DepthExceeded)
        );
    }

    #[test]
    fn external_explicit_values_hold_comparable_trees_and_round_trip() {
        let input = [0x28, 5, 0xa0, 3, 1, 1, 0xff];
        let tree = decode(&input);
        let expected = Asn1External::new(
            None,
            None,
            None,
            ExternalEncoding::SingleAsn1Type(Box::new(Asn1Boolean(true).into())),
        );
        assert_eq!(tree, Asn1Object::External(expected.clone()));
        let Asn1Object::External(value) = &tree else {
            panic!("expected external");
        };
        assert_eq!(value, &expected);
        assert_eq!(
            value.encoding(),
            &ExternalEncoding::SingleAsn1Type(Box::new(Asn1Boolean(true).into()))
        );
        assert_eq!(encode_member(&tree, EncodingType::Der).unwrap(), input);
        assert_eq!(
            tree.to_string(),
            "EXTERNAL\n  encoding [0]\n    BOOLEAN true\n"
        );
    }

    #[test]
    fn malformed_known_values_and_children_are_rejected_instead_of_becoming_unknown() {
        for input in [
            &b"\x05\x01\x00"[..],
            &b"\x02\x00"[..],
            &b"\x30\x01\x02"[..],
            &b"\xa0\x01\x02"[..],
        ] {
            assert!(Asn1Object::try_decode(input, Depth::DEFAULT).is_err());
        }
        let (used, value) = Asn1Object::try_decode(&[5, 0, 1, 1, 0], Depth::DEFAULT).unwrap();
        assert_eq!((used, value), (2, Asn1Object::Null));
    }

    #[test]
    fn encoders_report_short_buffers_and_content_lengths_match_actual_output() {
        for tree in [
            Asn1Object::Null,
            Asn1Object::Sequence(vec![Asn1Integer::from(7_u8).into()]),
            Asn1Object::Set(vec![Asn1Object::Null, Asn1Boolean(false).into()]),
            Asn1Tagged::primitive(&[0x80], &[1, 2]).unwrap().into(),
            Asn1Tagged::constructed(&[0x80], vec![Asn1Object::Null])
                .unwrap()
                .into(),
            decode(&[0x1f, 0x25, 0x81, 1, 0xaa]),
        ] {
            for rules in [EncodingType::Ber, EncodingType::Der] {
                let len = tree.encoded_len(rules);
                assert_eq!(
                    tree.encode(rules, &mut vec![0; len - 1]),
                    Err(Asn1Error::BufferTooSmall)
                );
                let mut content = vec![0; tree.content_len(rules)];
                assert_eq!(
                    tree.encode_content(rules, &mut content).unwrap(),
                    content.len()
                );
            }
        }
    }

    #[test]
    fn typed_getters_return_none_for_other_variants() {
        let tree = Asn1Object::Null;
        assert!(tree.as_sequence().is_none());
        assert!(tree.as_set().is_none());
        assert!(tree.as_integer().is_none());
        assert!(tree.as_oid().is_none());
        assert!(tree.as_octet_string().is_none());
        assert!(tree.as_bit_string().is_none());
        assert!(tree.as_tagged().is_none());
        let tree: Asn1Object = Asn1BitString::from_bits(&[0x80], 1).into();
        assert_eq!(tree.as_bit_string().unwrap().bit_len(), 1);
        assert_eq!(Asn1Object::from(Asn1Null), Asn1Object::Null);
    }

    #[test]
    fn public_tree_methods_document_their_timing_contracts() {
        for source in [
            include_str!("asn1_object.rs"),
            include_str!("asn1_object/tagged.rs"),
        ] {
            let mut has_timing = false;
            let mut count = 0;
            for line in source.split("#[cfg(test)]").next().unwrap().lines() {
                let line = line.trim();
                if line.starts_with("///") {
                    has_timing |= line.contains("常數時間") || line.contains("變動時間");
                    continue;
                }
                if line.starts_with("pub fn ") || line.starts_with("pub const fn ") {
                    assert!(has_timing, "missing timing contract: {line}");
                    count += 1;
                }
                if !line.is_empty() && !line.starts_with("#[") {
                    has_timing = false;
                }
            }
            assert!(count > 0);
        }
    }

    #[test]
    fn every_declared_universal_tag_decodes_to_its_own_variant_and_reencodes() {
        // 表格同時記錄常數名稱、獨立的線路向量與預期分支；新增 tag 必須同步補表。
        macro_rules! cases {
            ($(($tag:ident, $input:expr, $variant:pat)),* $(,)?) => {{
                let names = [$(stringify!($tag)),*];
                $(
                    let input: &[u8] = $input;
                    let tree = decode(input);
                    assert_eq!(tree.tag(), tag::$tag, "{}", stringify!($tag));
                    assert!(matches!(tree, $variant), "{}: {tree:?}", stringify!($tag));
                    assert_eq!(encode_member(&tree, EncodingType::Der).unwrap(), input, "{}", stringify!($tag));
                    assert!(tree.to_string().ends_with('\n'));
                )*
                names
            }};
        }
        let names = cases![
            (BOOLEAN, b"\x01\x01\x00", Asn1Object::Boolean(_)),
            (INTEGER, b"\x02\x01\x00", Asn1Object::Integer(_)),
            (BIT_STRING, b"\x03\x01\x00", Asn1Object::BitString(_)),
            (OCTET_STRING, b"\x04\x00", Asn1Object::OctetString(_)),
            (NULL, b"\x05\x00", Asn1Object::Null),
            (OBJECT_IDENTIFIER, b"\x06\x01\x00", Asn1Object::Oid(_)),
            (
                OBJECT_DESCRIPTOR,
                b"\x07\x00",
                Asn1Object::ObjectDescriptor(_)
            ),
            (EXTERNAL, b"\x28\x04\x81\x02AB", Asn1Object::External(_)),
            (REAL, b"\x09\x00", Asn1Object::Real(_)),
            (ENUMERATED, b"\x0a\x01\x00", Asn1Object::Enumerated(_)),
            (
                EMBEDDED_PDV,
                b"\x2b\x06\xa0\x02\x85\x00\x82\x00",
                Asn1Object::EmbeddedPdv(_)
            ),
            (UTF8_STRING, b"\x0c\x00", Asn1Object::Utf8String(_)),
            (RELATIVE_OID, b"\x0d\x01\x00", Asn1Object::RelativeOid(_)),
            (TIME, b"\x0e\x042024", Asn1Object::Time(_)),
            (SEQUENCE, b"\x30\x00", Asn1Object::Sequence(_)),
            (SET, b"\x31\x00", Asn1Object::Set(_)),
            (NUMERIC_STRING, b"\x12\x00", Asn1Object::NumericString(_)),
            (
                PRINTABLE_STRING,
                b"\x13\x00",
                Asn1Object::PrintableString(_)
            ),
            (TELETEX_STRING, b"\x14\x00", Asn1Object::TeletexString(_)),
            (VIDEOTEX_STRING, b"\x15\x00", Asn1Object::VideotexString(_)),
            (IA5_STRING, b"\x16\x00", Asn1Object::Ia5String(_)),
            (UTC_TIME, b"\x17\x0d230101000000Z", Asn1Object::UtcTime(_)),
            (
                GENERALIZED_TIME,
                b"\x18\x0f20230101000000Z",
                Asn1Object::GeneralizedTime(_)
            ),
            (GRAPHIC_STRING, b"\x19\x00", Asn1Object::GraphicString(_)),
            (VISIBLE_STRING, b"\x1a\x00", Asn1Object::VisibleString(_)),
            (GENERAL_STRING, b"\x1b\x00", Asn1Object::GeneralString(_)),
            (
                UNIVERSAL_STRING,
                b"\x1c\x00",
                Asn1Object::UniversalString(_)
            ),
            (
                CHARACTER_STRING,
                b"\x3d\x06\xa0\x02\x85\x00\x82\x00",
                Asn1Object::CharacterString(_)
            ),
            (BMP_STRING, b"\x1e\x00", Asn1Object::BmpString(_)),
            (DATE, b"\x1f\x1f\x0820240229", Asn1Object::Date(_)),
            (TIME_OF_DAY, b"\x1f\x20\x06123000", Asn1Object::TimeOfDay(_)),
            (
                DATE_TIME,
                b"\x1f\x21\x0e20240229123000",
                Asn1Object::DateTime(_)
            ),
            (DURATION, b"\x1f\x22\x021D", Asn1Object::Duration(_)),
            (OID_IRI, b"\x1f\x23\x06/ISO/0", Asn1Object::OidIri(_)),
            (
                RELATIVE_OID_IRI,
                b"\x1f\x24\x011",
                Asn1Object::RelativeOidIri(_)
            ),
        ];
        let declared: Vec<_> = include_str!("universal/tag.rs")
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub const "))
            .map(|rest| rest.split(':').next().unwrap())
            .collect();
        assert_eq!(declared, names);
    }
}
