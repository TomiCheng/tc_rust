//! 解碼側的「不知道型別」：整段 TLV 原樣擁有，不解讀。
//!
//! 給 schema 說 `ANY` 的欄位和不認識的東西。它只做三件事：存、借回去看、原樣寫回。
//! 造值不走這裡 —— 造值時型別是知道的，用型別化的值。

use alloc::vec::Vec;

use crate::asn1_ref::Asn1Ref;
use crate::decoding_options::DecodingOptions;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{Decode, Encode};

/// 整段 TLV，含表頭；建構時驗過是一個完整的元素。
/// Raw encodings are not canonicalised under CER either.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Any {
    raw: Vec<u8>,
    tag_len: usize,
    value_offset: usize,
    value_len: usize,
}

impl Asn1Any {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// 借回去當 [`Asn1Ref`] 用：看 tag、走子元素、`decode_as`。
    ///
    /// Uses the boundaries saved when the TLV was parsed, without resetting limits
    /// or reparsing an indefinite-length value. Constant time.
    pub fn as_ref(&self) -> Asn1Ref<'_> {
        Asn1Ref::from_validated_parts(&self.raw, self.tag_len, self.value_offset, self.value_len)
    }
}

impl From<&Asn1Ref<'_>> for Asn1Any {
    fn from(element: &Asn1Ref<'_>) -> Self {
        Self {
            raw: element.raw().to_vec(),
            tag_len: element.tag().len(),
            value_offset: element.value().as_ptr() as usize - element.raw().as_ptr() as usize,
            value_len: element.value().len(),
        }
    }
}

/// Preserve one complete TLV without assigning a content type.
impl<'a> Decode<'a> for Asn1Any {
    fn try_decode(buff: &'a [u8], options: DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, options)?;
        Ok((element.total_len(), Self::from(&element)))
    }
}

/// 原樣重送，不看 `rules`：它不知道內容是什麼，也就無從正規化 —— 這正是拿它
/// 保真的理由。`encode` 連長度的寫法都保留；`encode_tagged` 換了 tag 就只能
/// 重寫表頭，內容不變。
impl crate::EncodeContent for Asn1Any {
    fn content_len(&self, _: EncodingOptions) -> usize {
        self.as_ref().value().len()
    }

    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        let value = self.as_ref().value();
        out[..value.len()].copy_from_slice(value);
        Ok(value.len())
    }
}

impl crate::EncodeTagged for Asn1Any {}

impl Encode for Asn1Any {
    fn encoded_len(&self, _: EncodingOptions) -> usize {
        self.raw.len()
    }

    fn encode(&self, _: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
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
    use crate::EncodeTagged;
    use crate::asn1_ref::Asn1Class;
    use crate::universal::Asn1Boolean;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn an_unknown_context_specific_value_survives_a_round_trip_untouched() {
        // [3] IMPLICIT 某個東西，內容不知道是什麼；後面還有別的
        let input = [0x83, 0x03, 0xDE, 0xAD, 0x01, 0xAA];
        let (used, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();

        assert_eq!(used, 5);
        assert_eq!(any.raw(), &input[..5]);
        assert_eq!(any.as_ref().tag(), &[0x83]);
        assert_eq!(any.as_ref().value(), &[0xDE, 0xAD, 0x01]);
        assert_eq!(any.as_ref().class(), Asn1Class::ContextSpecific);

        let mut out = [0_u8; 8];
        let written = any.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input[..5]);
    }

    #[test]
    fn even_the_length_form_is_preserved_on_re_emission() {
        // 81 03 不是最短的長度寫法。原樣留著。
        let input = [0x04, 0x81, 0x03, 0xAA, 0xBB, 0xCC];
        let (_, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();

        let mut out = [0_u8; 8];
        let written = any.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input);
        assert_eq!(any.encoded_len(EncodingOptions::Der), 6);
    }

    #[test]
    fn retagging_rebuilds_the_header_but_keeps_the_contents() {
        let (_, any) = Asn1Any::try_decode(&[0x04, 0x81, 0x01, 0xAA], OPTIONS).unwrap();
        let mut out = [0_u8; 8];
        let written = any
            .encode_tagged(&[0x80], EncodingOptions::Der, &mut out)
            .unwrap();
        assert_eq!(&out[..written], &[0x80, 0x01, 0xAA], "換 tag 就得重寫表頭");
    }

    #[test]
    fn a_known_type_can_be_recovered_later_through_as_ref() {
        let (_, any) = Asn1Any::try_decode(&[0x01, 0x01, 0xFF], OPTIONS).unwrap();
        assert_eq!(
            any.as_ref().decode_as::<Asn1Boolean>(OPTIONS),
            Ok(Asn1Boolean(true))
        );
    }

    #[test]
    fn a_constructed_value_keeps_its_children_reachable() {
        let (_, any) = Asn1Any::try_decode(&[0x30, 0x04, 0x05, 0x00, 0x05, 0x00], OPTIONS).unwrap();
        assert!(any.as_ref().is_constructed());
        assert_eq!(any.as_ref().children(OPTIONS).count(), 2);
    }

    #[test]
    fn an_indefinite_length_value_re_parses_to_the_same_shape() {
        let input = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00];
        let (_, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();
        assert_eq!(any.as_ref().value(), &[0x05, 0x00]);
        assert_eq!(any.as_ref().children(OPTIONS).count(), 1);
    }

    #[test]
    fn non_der_input_is_re_emitted_as_is_not_normalised() {
        // BOOLEAN 真寫成 01 不是 DER；Asn1Any 不知道那是 BOOLEAN，所以原樣重送。
        let input = [0x01, 0x01, 0x01];
        let (_, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();
        let mut out = [0_u8; 8];
        let written = any.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input, "保真優先於正規化");
    }
}
