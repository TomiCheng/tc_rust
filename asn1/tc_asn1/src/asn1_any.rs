//! 解碼側的「不知道型別」：整段 TLV 原樣擁有，不解讀。
//!
//! 給 schema 說 `ANY` 的欄位和不認識的東西。它只做三件事：存、借回去看、原樣寫回。
//! 造值不走這裡 —— 造值時型別是知道的，用型別化的值。

use alloc::vec::Vec;

use crate::asn1_ref::Asn1Ref;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Decode, Encode};

/// 整段 TLV，含表頭；建構時驗過是一個完整的元素。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Any {
    raw: Vec<u8>,
}

impl Asn1Any {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// 借回去當 [`Asn1Ref`] 用：看 tag、走子元素、`decode_as`。
    ///
    /// 每次重解表頭。定長只是幾個位元組；不定長要走到 EOC。
    pub fn as_ref(&self) -> Asn1Ref<'_> {
        // 建構時只收 parse 成功的東西，所以這裡不會失敗。
        Asn1Ref::parse(&self.raw, Depth::DEFAULT).expect("Asn1Any holds a validated TLV")
    }
}

impl From<&Asn1Ref<'_>> for Asn1Any {
    fn from(element: &Asn1Ref<'_>) -> Self {
        Self {
            raw: element.raw().to_vec(),
        }
    }
}

/// 沒有固定 tag，所以不走 `DecodeContent` 的 blanket，直接解整個 TLV。
impl<'a> Decode<'a> for Asn1Any {
    fn try_decode(buff: &'a [u8], depth: Depth) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, depth)?;
        Ok((element.total_len(), Self::from(&element)))
    }
}

/// 原樣重送，不看 `rules`：它不知道內容是什麼，也就無從正規化 —— 這正是拿它
/// 保真的理由。`encode` 連長度的寫法都保留；`encode_tagged` 換了 tag 就只能
/// 重寫表頭，內容不變。
impl Encode for Asn1Any {
    fn tag(&self) -> &[u8] {
        self.as_ref().tag()
    }
    fn content_len(&self, _: EncodingType) -> usize {
        self.as_ref().value().len()
    }
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let value = self.as_ref().value();
        out[..value.len()].copy_from_slice(value);
        Ok(value.len())
    }
    fn encoded_len(&self, _: EncodingType) -> usize {
        self.raw.len()
    }
    fn encode(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.raw.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.raw);
        Ok(self.raw.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_ref::Asn1Class;
    use crate::universal::Asn1Boolean;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn an_unknown_context_specific_value_survives_a_round_trip_untouched() {
        // [3] IMPLICIT 某個東西，內容不知道是什麼；後面還有別的
        let input = [0x83, 0x03, 0xDE, 0xAD, 0x01, 0xAA];
        let (used, any) = Asn1Any::try_decode(&input, DEPTH).unwrap();

        assert_eq!(used, 5);
        assert_eq!(any.raw(), &input[..5]);
        assert_eq!(any.as_ref().tag(), &[0x83]);
        assert_eq!(any.as_ref().value(), &[0xDE, 0xAD, 0x01]);
        assert_eq!(any.as_ref().class(), Asn1Class::ContextSpecific);

        let mut out = [0_u8; 8];
        let written = any.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input[..5]);
    }

    #[test]
    fn even_the_length_form_is_preserved_on_re_emission() {
        // 81 03 不是最短的長度寫法。原樣留著。
        let input = [0x04, 0x81, 0x03, 0xAA, 0xBB, 0xCC];
        let (_, any) = Asn1Any::try_decode(&input, DEPTH).unwrap();

        let mut out = [0_u8; 8];
        let written = any.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input);
        assert_eq!(any.encoded_len(EncodingType::Der), 6);
    }

    #[test]
    fn retagging_rebuilds_the_header_but_keeps_the_contents() {
        let (_, any) = Asn1Any::try_decode(&[0x04, 0x81, 0x01, 0xAA], DEPTH).unwrap();
        let mut out = [0_u8; 8];
        let written = any
            .encode_tagged(&[0x80], EncodingType::Der, &mut out)
            .unwrap();
        assert_eq!(&out[..written], &[0x80, 0x01, 0xAA], "換 tag 就得重寫表頭");
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
        assert!(any.as_ref().is_constructed());
        assert_eq!(any.as_ref().children(DEPTH).count(), 2);
    }

    #[test]
    fn an_indefinite_length_value_re_parses_to_the_same_shape() {
        let input = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00];
        let (_, any) = Asn1Any::try_decode(&input, DEPTH).unwrap();
        assert_eq!(any.as_ref().value(), &[0x05, 0x00]);
        assert_eq!(any.as_ref().children(DEPTH).count(), 1);
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
