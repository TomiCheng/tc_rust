//! ASN.1 `BOOLEAN`。

use crate::depth::Depth;
use crate::length::{self, Length};
use crate::{Asn1Error, EncodingType, TryDecode, TryEncode};

/// `BOOLEAN` 的識別位元組：universal 1，primitive。
const TAG: u8 = 0x01;

/// 完整編碼的位元組數：tag、長度、一個內容位元組。
const ENCODED_LEN: usize = 3;

/// 一個 ASN.1 `BOOLEAN`。
///
/// 內容剛好一個位元組。BER 與 DL 把任何非零值當成真，DER 規定真必須是 `FF`
/// （X.690 11.1）。寫出時三種規則都寫 `FF` —— 那在三者下都合法，也讓輸出
/// 直接就是正規形式。差別只在讀入：非 `FF` 的真值解得出來，但重編成 DER 時
/// 位元組會變，往返比較因此會正確地判定它不是 DER。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1Boolean {
    value: bool,
}

impl Asn1Boolean {
    /// 建立一個 `BOOLEAN`。
    pub const fn new(value: bool) -> Self {
        Self { value }
    }

    /// 常數時間：取出布林值。
    pub const fn value(self) -> bool {
        self.value
    }
}

impl From<bool> for Asn1Boolean {
    fn from(value: bool) -> Self {
        Self::new(value)
    }
}

impl TryEncode for Asn1Boolean {
    type Error = Asn1Error;

    /// 常數時間：永遠是 3，與值和規則都無關。
    fn try_encode_len(&self, encoding_type: EncodingType) -> Result<usize, Self::Error> {
        let _ = encoding_type;
        Ok(ENCODED_LEN)
    }

    /// 常數時間：真寫 `01 01 FF`，假寫 `01 01 00`。
    ///
    /// 內容位元組由值算出而不是分支選出，所以耗時不隨值改變。長度分支只看
    /// `buff`，那是公開量。
    fn try_encode(
        &self,
        encoding_type: EncodingType,
        buff: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = encoding_type;

        let output = buff
            .get_mut(..ENCODED_LEN)
            .ok_or(Asn1Error::BufferTooSmall)?;
        output[0] = TAG;
        output[1] = 1;
        // true → 1 → 0xFF，false → 0 → 0x00，沒有分支。
        output[2] = u8::from(self.value).wrapping_neg();
        Ok(ENCODED_LEN)
    }
}

impl TryDecode for Asn1Boolean {
    type Error = Asn1Error;

    /// 變動時間：分支只依編碼結構。
    ///
    /// 寬鬆照 BER：任何非零的內容位元組都是真，非最短的長度形式也接受。
    fn try_decode(buff: &[u8], depth: Depth) -> Result<(usize, Self), Self::Error> {
        // 葉節點不會遞迴，深度預算由 `Asn1Object` 消耗。
        let _ = depth;

        let (tag, rest) = buff.split_first().ok_or(Asn1Error::Truncated)?;
        if *tag != TAG {
            return Err(Asn1Error::UnexpectedTag);
        }

        let (consumed, length) = length::decode(rest)?;
        let Length::Definite(1) = length else {
            // 內容必須剛好一個位元組；不定長度只用於 constructed 編碼。
            return Err(Asn1Error::MalformedValue);
        };

        let octet = *rest.get(consumed).ok_or(Asn1Error::Truncated)?;
        Ok((1 + consumed + 1, Self::new(octet != 0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH: Depth = Depth::DEFAULT;

    const RULES: [EncodingType; 3] = [EncodingType::Ber, EncodingType::Dl, EncodingType::Der];

    #[test]
    fn every_rule_writes_true_as_all_ones() {
        for rule in RULES {
            let mut buffer = [0xAA_u8; 5];
            let written = Asn1Boolean::new(true)
                .try_encode(rule, &mut buffer)
                .unwrap();

            assert_eq!(written, 3, "{rule:?}");
            assert_eq!(&buffer[..written], &[0x01, 0x01, 0xFF], "{rule:?}");
            assert_eq!(buffer[3], 0xAA, "只該寫入前三個位元組");
        }
    }

    #[test]
    fn false_is_written_as_a_zero_octet() {
        let mut buffer = [0_u8; 5];
        let written = Asn1Boolean::new(false)
            .try_encode(EncodingType::Der, &mut buffer)
            .unwrap();

        assert_eq!(&buffer[..written], &[0x01, 0x01, 0x00]);
    }

    #[test]
    fn the_reported_length_matches_what_is_written() {
        for rule in RULES {
            for value in [false, true] {
                let boolean = Asn1Boolean::new(value);
                let mut buffer = [0_u8; 5];

                let expected = boolean.try_encode_len(rule).unwrap();
                let written = boolean.try_encode(rule, &mut buffer).unwrap();

                assert_eq!(written, expected, "{rule:?} {value}");
            }
        }
    }

    #[test]
    fn both_values_survive_a_round_trip() {
        for value in [false, true] {
            let mut buffer = [0_u8; 5];
            let written = Asn1Boolean::new(value)
                .try_encode(EncodingType::Der, &mut buffer)
                .unwrap();

            let (consumed, decoded) = Asn1Boolean::try_decode(&buffer[..written], DEPTH).unwrap();
            assert_eq!(consumed, written);
            assert_eq!(decoded.value(), value);
        }
    }

    #[test]
    fn any_non_zero_octet_decodes_as_true() {
        // BER 與 DL 允許；DER 只允許 0xFF，但解碼一律寬鬆。
        for octet in [0x01_u8, 0x7F, 0x80, 0xFE, 0xFF] {
            let (consumed, decoded) = Asn1Boolean::try_decode(&[0x01, 0x01, octet], DEPTH).unwrap();

            assert_eq!(consumed, 3);
            assert!(decoded.value(), "octet {octet:#04X}");
        }
    }

    #[test]
    fn a_non_canonical_true_does_not_survive_re_encoding_as_der() {
        // 這就是往返比較判定「不是 DER」的機制。
        let input = [0x01_u8, 0x01, 0x01];
        let (_, decoded) = Asn1Boolean::try_decode(&input, DEPTH).unwrap();

        let mut buffer = [0_u8; 5];
        let written = decoded.try_encode(EncodingType::Der, &mut buffer).unwrap();

        assert_ne!(&buffer[..written], &input[..]);
    }

    #[test]
    fn redundant_ber_length_forms_are_accepted() {
        let (consumed, decoded) =
            Asn1Boolean::try_decode(&[0x01, 0x81, 0x01, 0xFF], DEPTH).unwrap();

        assert_eq!(consumed, 4);
        assert!(decoded.value());
    }

    #[test]
    fn a_tag_other_than_boolean_is_rejected() {
        // 0x05 是 NULL。
        assert_eq!(
            Asn1Boolean::try_decode(&[0x05, 0x01, 0xFF], DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn contents_of_any_length_but_one_are_rejected() {
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x00], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x02, 0xFF, 0xFF], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_indefinite_length_boolean_is_rejected() {
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x80], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_input_too_short_to_hold_a_boolean_is_rejected() {
        assert_eq!(
            Asn1Boolean::try_decode(&[], DEPTH),
            Err(Asn1Error::Truncated)
        );
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01], DEPTH),
            Err(Asn1Error::Truncated)
        );
        assert_eq!(
            Asn1Boolean::try_decode(&[0x01, 0x01], DEPTH),
            Err(Asn1Error::Truncated)
        );
    }

    #[test]
    fn a_buffer_shorter_than_the_encoding_is_rejected() {
        assert_eq!(
            Asn1Boolean::new(true).try_encode(EncodingType::Der, &mut [0; 2]),
            Err(Asn1Error::BufferTooSmall)
        );
    }
}
