//! ASN.1 `NULL`。

use crate::depth::Depth;
use crate::length::{self, Length};
use crate::{Asn1Error, EncodingType, TryDecode, TryEncode};

/// `NULL` 的識別位元組：universal 5，primitive。
const TAG: u8 = 0x05;

/// `NULL` 寫出去的樣子：識別位元組加零長度。
const ENCODED: [u8; 2] = [TAG, 0x00];

/// 一個 ASN.1 `NULL`。
///
/// 沒有內容，所以沒有欄位。三種規則下的編碼完全相同 —— 內容是空的，
/// 不定長度與字串分段都無從發生，`Der` 的正規化也沒有東西可以正規化。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1Null;

impl TryEncode for Asn1Null {
    type Error = Asn1Error;

    /// 常數時間：永遠是 2，與規則無關。
    fn try_encode_len(&self, encoding_type: EncodingType) -> Result<usize, Self::Error> {
        let _ = encoding_type;
        Ok(ENCODED.len())
    }

    /// 常數時間：寫出 `05 00`。只依 `buff` 的長度分支，而長度是公開量。
    fn try_encode(
        &self,
        encoding_type: EncodingType,
        buff: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = encoding_type;

        let output = buff
            .get_mut(..ENCODED.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        output.copy_from_slice(&ENCODED);
        Ok(ENCODED.len())
    }
}

impl TryDecode for Asn1Null {
    type Error = Asn1Error;

    /// 變動時間：分支只依編碼結構。
    ///
    /// 寬鬆照 BER，所以非最短的長度形式也接受 —— `05 81 00` 和 `05 00` 一樣是
    /// 合法的 `NULL`。要求輸入必須是 DER 的地方靠往返比較判定，不在這裡。
    fn try_decode(buff: &[u8], depth: Depth) -> Result<(usize, Self), Self::Error> {
        // 葉節點不會遞迴，深度預算由 `Asn1Object` 消耗。
        let _ = depth;

        let (tag, rest) = buff.split_first().ok_or(Asn1Error::Truncated)?;
        if *tag != TAG {
            return Err(Asn1Error::UnexpectedTag);
        }

        let (consumed, length) = length::decode(rest)?;
        match length {
            Length::Definite(0) => Ok((1 + consumed, Self)),
            // NULL 沒有內容；不定長度只用於 constructed 編碼。
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH: Depth = Depth::DEFAULT;

    const RULES: [EncodingType; 3] = [EncodingType::Ber, EncodingType::Dl, EncodingType::Der];

    #[test]
    fn every_rule_encodes_null_as_the_same_two_bytes() {
        for rule in RULES {
            let mut buffer = [0xAA_u8; 4];
            let written = Asn1Null.try_encode(rule, &mut buffer).unwrap();

            assert_eq!(written, 2, "{rule:?}");
            assert_eq!(&buffer[..written], &[0x05, 0x00], "{rule:?}");
            assert_eq!(buffer[2], 0xAA, "只該寫入前兩個位元組");
        }
    }

    #[test]
    fn the_reported_length_matches_what_is_written() {
        for rule in RULES {
            let mut buffer = [0_u8; 4];
            let expected = Asn1Null.try_encode_len(rule).unwrap();
            let written = Asn1Null.try_encode(rule, &mut buffer).unwrap();

            assert_eq!(written, expected, "{rule:?}");
        }
    }

    #[test]
    fn a_buffer_shorter_than_the_encoding_is_rejected() {
        assert_eq!(
            Asn1Null.try_encode(EncodingType::Der, &mut []),
            Err(Asn1Error::BufferTooSmall)
        );
        assert_eq!(
            Asn1Null.try_encode(EncodingType::Der, &mut [0; 1]),
            Err(Asn1Error::BufferTooSmall)
        );
    }

    #[test]
    fn decoding_consumes_exactly_the_two_bytes_and_leaves_the_rest() {
        let (consumed, value) =
            Asn1Null::try_decode(&[0x05, 0x00, 0x02, 0x01, 0x05], DEPTH).unwrap();

        assert_eq!(consumed, 2);
        assert_eq!(value, Asn1Null);
    }

    #[test]
    fn a_tag_other_than_null_is_rejected() {
        // 0x02 是 INTEGER。
        assert_eq!(
            Asn1Null::try_decode(&[0x02, 0x00], DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn redundant_ber_length_forms_decode_as_null() {
        // 零長度寫成長式不是 DER，但是合法的 BER。
        assert_eq!(
            Asn1Null::try_decode(&[0x05, 0x81, 0x00], DEPTH).unwrap().0,
            3
        );
        assert_eq!(
            Asn1Null::try_decode(&[0x05, 0x82, 0x00, 0x00], DEPTH)
                .unwrap()
                .0,
            4
        );
    }

    #[test]
    fn an_indefinite_length_null_is_rejected() {
        // 不定長度只用於 constructed 編碼，NULL 是 primitive。
        assert_eq!(
            Asn1Null::try_decode(&[0x05, 0x80], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn a_null_carrying_contents_is_rejected() {
        assert_eq!(
            Asn1Null::try_decode(&[0x05, 0x01, 0x00], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_input_too_short_to_hold_a_null_is_rejected() {
        assert_eq!(Asn1Null::try_decode(&[], DEPTH), Err(Asn1Error::Truncated));
        assert_eq!(
            Asn1Null::try_decode(&[0x05], DEPTH),
            Err(Asn1Error::Truncated)
        );
    }
}
