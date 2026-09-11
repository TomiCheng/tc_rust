//! 不知道型別的值：tag 與內容原樣擁有，不解讀。
//!
//! 給 schema 說 `ANY` 的欄位、不認識的 extension、以及任何要原樣重送的東西。
//! 它不重編，所以拿它保真是安全的。

use alloc::vec::Vec;

use crate::asn1_ref::{Asn1Class, Asn1Ref};
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Any {
    tag: Vec<u8>,
    value: Vec<u8>,
}

impl Asn1Any {
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// 借回去當 [`Asn1Ref`] 用：走子元素、`decode_as`。
    pub fn as_ref(&self) -> Asn1Ref<'_> {
        Asn1Ref::from_parts(&self.tag, &self.value)
    }

    pub fn class(&self) -> Asn1Class {
        self.as_ref().class()
    }

    pub fn is_constructed(&self) -> bool {
        self.as_ref().is_constructed()
    }
}

impl From<&Asn1Ref<'_>> for Asn1Any {
    fn from(element: &Asn1Ref<'_>) -> Self {
        Self {
            tag: element.tag().to_vec(),
            value: element.value().to_vec(),
        }
    }
}

/// 沒有固定 tag，所以不走 `TryDecodeContent` 的 blanket，直接實作整個 TLV 的解碼。
impl<'a> TryDecode<'a> for Asn1Any {
    fn try_decode(buff: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, depth)?;
        Ok((element.total_len(), Self::from(&element)))
    }
}

impl Encode for Asn1Any {
    fn tag(&self) -> &[u8] {
        &self.tag
    }
    fn content_len(&self, _: EncodingType) -> usize {
        self.value.len()
    }
    /// 原樣寫出，不看 `rules`：它不知道內容是什麼，也就無從正規化。
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.value.len()].copy_from_slice(&self.value);
        Ok(self.value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::universal::Asn1Boolean;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn an_unknown_context_specific_value_survives_a_round_trip_untouched() {
        // [3] IMPLICIT 某個東西，內容不知道是什麼
        let input = [0x83, 0x03, 0xDE, 0xAD, 0x01, 0xAA];
        let (used, any) = Asn1Any::try_decode(&input, DEPTH).unwrap();

        assert_eq!(used, 5);
        assert_eq!(any.tag(), &[0x83]);
        assert_eq!(any.value(), &[0xDE, 0xAD, 0x01]);
        assert_eq!(any.class(), Asn1Class::ContextSpecific);
        assert!(!any.is_constructed());

        let mut out = [0_u8; 8];
        let written = any.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input[..5]);
    }

    #[test]
    fn a_known_type_can_be_recovered_later_through_as_ref() {
        let (_, any) = Asn1Any::try_decode(&[0x01, 0x01, 0xFF], DEPTH).unwrap();
        assert_eq!(
            any.as_ref().decode_as::<Asn1Boolean>(DEPTH),
            Ok(Asn1Boolean(true))
        );
    }

    #[test]
    fn a_constructed_value_keeps_its_children_reachable() {
        let (_, any) = Asn1Any::try_decode(&[0x30, 0x04, 0x05, 0x00, 0x05, 0x00], DEPTH).unwrap();
        assert!(any.is_constructed());
        assert_eq!(any.as_ref().children(DEPTH).count(), 2);
    }

    #[test]
    fn non_der_input_is_re_emitted_as_is_not_normalised() {
        // BOOLEAN 真寫成 01 不是 DER；Asn1Any 不知道那是 BOOLEAN，所以原樣重送。
        let input = [0x01, 0x01, 0x01];
        let (_, any) = Asn1Any::try_decode(&input, DEPTH).unwrap();
        let mut out = [0_u8; 8];
        let written = any.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input, "保真優先於正規化");
    }
}
