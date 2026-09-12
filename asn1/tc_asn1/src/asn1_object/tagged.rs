//! 非 universal 標記；是否為 EXPLICIT 必須由呼叫端的 schema 決定。

use alloc::vec::Vec;

use super::{Asn1Object, children_len, decode_children, encode_children};
use crate::asn1_ref::parse_tag;
use crate::universal::{copy_encodings, tag_key};
use crate::{Asn1Class, Asn1Error, Asn1Ref, Depth, Encode, EncodingType, TryDecodeContent};

/// 非 universal 標記的值，保留標記與可解讀的子樹。
///
/// 識別位元組必須完整，號碼限於 `u64`；超過回傳 [`Asn1Error::TagOverflow`]。
/// constructed 可能是 EXPLICIT，也可能是 IMPLICIT 的結構，單憑位元組無法區分。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asn1Tagged {
    /// 識別位元組，constructed 位與內容一致。
    tag: Vec<u8>,
    content: TaggedContent,
}

/// 標記的內容；primitive 的底層型別須由 schema 指定。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaggedContent {
    /// constructed 內容逐一解成子元素，不推斷 EXPLICIT 或 IMPLICIT。
    Constructed(Vec<Asn1Object>),
    /// primitive 保留原始內容位元組。
    Primitive(Vec<u8>),
}

impl Asn1Tagged {
    /// 接收子元素並設定 constructed 位。變動時間：分支只依編碼結構。
    pub fn constructed(tag: &[u8], children: Vec<Asn1Object>) -> Result<Self, Asn1Error> {
        let mut tag = checked_tag(tag)?;
        tag[0] |= 0x20;
        Ok(Self {
            tag,
            content: TaggedContent::Constructed(children),
        })
    }

    /// 複製原始內容並清除 constructed 位。變動時間：分支只依編碼結構。
    pub fn primitive(tag: &[u8], content: &[u8]) -> Result<Self, Asn1Error> {
        let mut tag = checked_tag(tag)?;
        tag[0] &= !0x20;
        Ok(Self {
            tag,
            content: TaggedContent::Primitive(content.to_vec()),
        })
    }

    /// 借用識別位元組。常數時間。
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// 取得標記類別。常數時間。
    pub fn class(&self) -> Asn1Class {
        Asn1Class::of(self.tag[0])
    }

    /// 取得標記號碼。常數時間：識別位元組有固定的十一位元組上限。
    pub fn number(&self) -> u64 {
        tag_key(&self.tag).expect("validated tag fits in u64").1
    }

    /// 判斷是否有子元素結構。常數時間。
    pub fn is_constructed(&self) -> bool {
        self.tag[0] & 0x20 != 0
    }

    /// 借用內容。常數時間。
    pub fn content(&self) -> &TaggedContent {
        &self.content
    }

    /// 依呼叫端的 schema 當成 EXPLICIT，借用唯一的子元素。常數時間。
    ///
    /// 不推斷標記方式；primitive 或子元素數量不是一個時回傳 `MalformedValue`。
    pub fn explicit(&self) -> Result<&Asn1Object, Asn1Error> {
        match &self.content {
            TaggedContent::Constructed(children) if children.len() == 1 => Ok(&children[0]),
            _ => Err(Asn1Error::MalformedValue),
        }
    }

    /// 借用 constructed 的子元素，可用於 IMPLICIT 的結構。常數時間。
    pub fn children(&self) -> Option<&[Asn1Object]> {
        match &self.content {
            TaggedContent::Constructed(children) => Some(children),
            TaggedContent::Primitive(_) => None,
        }
    }

    /// 依 schema 指定的型別解讀 primitive 內容。變動時間：分支只依編碼結構。
    ///
    /// constructed 回傳 `MalformedValue`；其子元素請用 [`Self::children`]。
    pub fn implicit_as<T: for<'a> TryDecodeContent<'a>>(
        &self,
        depth: Depth,
    ) -> Result<T, Asn1Error> {
        match &self.content {
            TaggedContent::Primitive(bytes) => T::try_decode_content(bytes, depth),
            TaggedContent::Constructed(_) => Err(Asn1Error::MalformedValue),
        }
    }

    pub(super) fn from_ref(element: &Asn1Ref<'_>, depth: Depth) -> Result<Self, Asn1Error> {
        let tag = checked_tag(element.tag())?;
        let content = if element.is_constructed() {
            TaggedContent::Constructed(decode_children(element, depth)?)
        } else {
            TaggedContent::Primitive(element.value().to_vec())
        };
        Ok(Self { tag, content })
    }
}

fn checked_tag(tag: &[u8]) -> Result<Vec<u8>, Asn1Error> {
    if parse_tag(tag)?.len() != tag.len() {
        return Err(Asn1Error::TrailingData);
    }
    if Asn1Class::of(tag[0]) == Asn1Class::Universal {
        return Err(Asn1Error::UnexpectedTag);
    }
    tag_key(tag)?;
    Ok(tag.to_vec())
}

impl Encode for Asn1Tagged {
    /// 借用識別位元組。常數時間。
    fn tag(&self) -> &[u8] {
        self.tag()
    }

    /// 計算內容長度。變動時間：分支只依編碼結構。
    fn content_len(&self, rules: EncodingType) -> usize {
        match &self.content {
            TaggedContent::Constructed(children) => children_len(children, rules),
            TaggedContent::Primitive(bytes) => bytes.len(),
        }
    }

    /// 依原順序編碼子元素或複製原始內容。變動時間：分支只依編碼結構。
    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match &self.content {
            TaggedContent::Constructed(children) => encode_children(children, rules, out),
            TaggedContent::Primitive(bytes) => {
                copy_encodings(core::iter::once(bytes.as_slice()), out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::universal::encode_member;
    use crate::{Asn1Boolean, Asn1Integer, TryDecode};
    use alloc::{string::ToString, vec};

    #[test]
    fn explicit_context_tags_decode_their_single_child_and_round_trip() {
        let input = [0xa0, 3, 2, 1, 2];
        let (_, tree) = Asn1Object::try_decode(&input, Depth::DEFAULT).unwrap();
        let tagged = tree.as_tagged().unwrap();
        assert_eq!(tagged.class(), Asn1Class::ContextSpecific);
        assert_eq!(tagged.number(), 0);
        assert!(tagged.is_constructed());
        assert_eq!(tagged.explicit().unwrap(), &Asn1Integer::from(2_u8).into());
        assert_eq!(tagged.children().unwrap().len(), 1);
        assert_eq!(
            tagged.implicit_as::<Asn1Boolean>(Depth::DEFAULT),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(tree.to_string(), "[CONTEXT 0]\n  INTEGER 2\n");
        assert_eq!(encode_member(&tree, EncodingType::Der).unwrap(), input);
    }

    #[test]
    fn primitive_context_tags_require_a_schema_to_interpret_their_contents() {
        let input = [0x80, 1, 0xff];
        let (_, tree) = Asn1Object::try_decode(&input, Depth::DEFAULT).unwrap();
        let tagged = tree.as_tagged().unwrap();
        assert_eq!(tagged.content(), &TaggedContent::Primitive(vec![0xff]));
        assert_eq!(
            tagged.implicit_as::<Asn1Boolean>(Depth::DEFAULT),
            Ok(Asn1Boolean(true))
        );
        assert_eq!(tagged.explicit(), Err(Asn1Error::MalformedValue));
        assert!(tagged.children().is_none());
        assert!(!tagged.is_constructed());
        assert_eq!(tree.to_string(), "[CONTEXT 0] (1 bytes) ff\n");
        assert_eq!(encode_member(&tree, EncodingType::Der).unwrap(), input);
    }

    #[test]
    fn constructors_set_the_constructed_bit_and_preserve_class_and_number() {
        for tag in [&[0x41][..], &[0x61][..]] {
            let value = Asn1Tagged::constructed(tag, vec![Asn1Object::Null]).unwrap();
            assert_eq!(value.tag(), &[0x61]);
            assert_eq!(value.class(), Asn1Class::Application);
            assert_eq!(value.number(), 1);
            assert_eq!(
                Asn1Object::from(value).to_string(),
                "[APPLICATION 1]\n  NULL\n"
            );
        }
        for tag in [&[0xc2][..], &[0xe2][..]] {
            let value = Asn1Tagged::primitive(tag, &[]).unwrap();
            assert_eq!(value.tag(), &[0xc2]);
            assert_eq!(value.class(), Asn1Class::Private);
            assert_eq!(value.number(), 2);
            assert_eq!(
                Asn1Object::from(value).to_string(),
                "[PRIVATE 2] (0 bytes)\n"
            );
        }
        let high = Asn1Tagged::constructed(&[0x9f, 0x81, 0], vec![]).unwrap();
        assert_eq!(high.tag(), &[0xbf, 0x81, 0]);
        assert_eq!(high.number(), 128);
        assert_eq!(high.explicit(), Err(Asn1Error::MalformedValue));
        let multiple =
            Asn1Tagged::constructed(&[0xa0], vec![Asn1Object::Null, Asn1Object::Null]).unwrap();
        assert_eq!(multiple.explicit(), Err(Asn1Error::MalformedValue));
    }

    #[test]
    fn tag_validation_rejects_universal_incomplete_nonminimal_and_trailing_identifiers() {
        for (tag, error) in [
            (&[][..], Asn1Error::Truncated),
            (&[0x9f, 0x81][..], Asn1Error::Truncated),
            (&[0x9f, 0x80, 0x20][..], Asn1Error::NonMinimalTag),
            (&[0x9f, 0x1e][..], Asn1Error::NonMinimalTag),
            (&[0x80, 0][..], Asn1Error::TrailingData),
            (&[0x04][..], Asn1Error::UnexpectedTag),
            (&[0x24][..], Asn1Error::UnexpectedTag),
        ] {
            assert_eq!(Asn1Tagged::primitive(tag, &[]), Err(error));
            assert_eq!(Asn1Tagged::constructed(tag, vec![]), Err(error));
        }
    }

    #[test]
    fn tag_numbers_accept_u64_maximum_and_reject_larger_values_before_exposure() {
        let mut tag = vec![0x9f, 0x81];
        tag.extend_from_slice(&[0xff; 8]);
        tag.push(0x7f);
        let value = Asn1Tagged::primitive(&tag, &[]).unwrap();
        assert_eq!(value.number(), u64::MAX);
        let encoded = encode_member(&value, EncodingType::Der).unwrap();
        let tree = Asn1Object::try_decode(&encoded, Depth::DEFAULT).unwrap().1;
        assert_eq!(tree.as_tagged().unwrap().number(), u64::MAX);
        tag[1] = 0x82;
        assert_eq!(
            Asn1Tagged::primitive(&tag, &[]),
            Err(Asn1Error::TagOverflow)
        );
        tag.push(0);
        assert_eq!(
            Asn1Tagged::primitive(&tag, &[]),
            Err(Asn1Error::TrailingData)
        );
        tag[10] = 0xff;
        assert_eq!(
            Asn1Tagged::primitive(&tag, &[]),
            Err(Asn1Error::TagOverflow)
        );
        tag.push(0);
        assert_eq!(
            Asn1Object::try_decode(&tag, Depth::DEFAULT),
            Err(Asn1Error::TagOverflow)
        );
    }
}
