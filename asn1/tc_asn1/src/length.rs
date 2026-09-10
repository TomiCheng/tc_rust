//! 長度位元組（length octets）的編解碼。
//!
//! 編碼一律寫最短的定長形式，三種規則都一樣 —— 它們唯一的差別是要不要用
//! 不定長，而那是 constructed 型別的選擇，不是這裡的。
//!
//! 解碼寬鬆照 BER：接受非最短的長式，也把不定長當成一個**值**回傳而不是錯誤。

use crate::asn1_error::Asn1Error;

/// 短式能表示的最大長度，也是短式與長式的分界。
const SHORT_FORM_MAX: u8 = 0x7F;

/// 不定長度的第一個位元組。
const INDEFINITE: u8 = 0x80;

/// X.690 保留這個值，沒有定義意義。
const RESERVED: u8 = 0xFF;

/// 不定長度內容的結尾標記（end-of-contents）。
pub(crate) const END_OF_CONTENTS: [u8; 2] = [0x00, 0x00];

/// 一個 TLV 的長度欄位說了什麼。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Length {
    /// 內容有這麼多位元組。
    Definite(usize),

    /// 內容長度未知，讀到 [`END_OF_CONTENTS`] 為止。只有 BER 會出現。
    Indefinite,
}

/// 長度編碼後佔用的位元組數。
pub(crate) const fn encoded_len(length: usize) -> usize {
    if length <= SHORT_FORM_MAX as usize {
        return 1;
    }

    let mut significant = 0;
    let mut remaining = length;
    while remaining > 0 {
        significant += 1;
        remaining >>= 8;
    }
    1 + significant
}

/// 變動時間：把長度寫進 `buff` 前端，回傳寫入的位元組數。
///
/// 永遠是最短的定長形式。分支只依長度的大小，而長度是公開量。
pub(crate) fn encode(length: usize, buff: &mut [u8]) -> Result<usize, Asn1Error> {
    let total = encoded_len(length);
    let output = buff.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;

    if total == 1 {
        output[0] = length as u8;
        return Ok(1);
    }

    // 長式：第一個位元組的低 7 位是後續位元組數。
    let count = total - 1;
    output[0] = INDEFINITE | (count as u8);
    for (index, slot) in output[1..].iter_mut().enumerate() {
        let shift = 8 * (count - 1 - index);
        *slot = (length >> shift) as u8;
    }
    Ok(total)
}

/// 變動時間：由 `buff` 前端解出長度欄位，回傳消耗的位元組數與長度。
///
/// 寬鬆解碼：長式的前導零會被接受（BER 允許），不定長度回
/// [`Length::Indefinite`]。要求輸入必須是 DER 的地方靠往返比較判定，不在這裡。
pub(crate) fn decode(buff: &[u8]) -> Result<(usize, Length), Asn1Error> {
    let (first, rest) = buff.split_first().ok_or(Asn1Error::Truncated)?;

    if *first <= SHORT_FORM_MAX {
        return Ok((1, Length::Definite(usize::from(*first))));
    }
    if *first == INDEFINITE {
        return Ok((1, Length::Indefinite));
    }
    if *first == RESERVED {
        return Err(Asn1Error::MalformedValue);
    }

    let count = usize::from(first & SHORT_FORM_MAX);
    let octets = rest.get(..count).ok_or(Asn1Error::Truncated)?;

    let mut length: usize = 0;
    for byte in octets {
        // 用 checked_mul 而不是 checked_shl：後者只檢查位移量是否小於位元寬度，
        // 高位被移掉它不管，等於沒有防護。
        length = length
            .checked_mul(256)
            .and_then(|shifted| shifted.checked_add(usize::from(*byte)))
            .ok_or(Asn1Error::LengthOverflow)?;
    }

    Ok((1 + count, Length::Definite(length)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_lengths_round_trip_through_both_forms() {
        for length in [0_usize, 1, 127, 128, 255, 256, 65_535, 65_536, 1 << 24] {
            let mut buffer = [0_u8; 16];
            let written = encode(length, &mut buffer).unwrap();
            assert_eq!(written, encoded_len(length), "length {length}");

            let (consumed, decoded) = decode(&buffer[..written]).unwrap();
            assert_eq!(consumed, written, "length {length}");
            assert_eq!(decoded, Length::Definite(length));
        }
    }

    #[test]
    fn the_short_form_boundary_sits_at_one_hundred_and_twenty_eight() {
        let mut buffer = [0_u8; 16];
        assert_eq!(encode(127, &mut buffer).unwrap(), 1);
        assert_eq!(buffer[0], 0x7F);
        assert_eq!(encode(128, &mut buffer).unwrap(), 2);
        assert_eq!(&buffer[..2], &[0x81, 0x80]);
    }

    #[test]
    fn the_encoder_always_chooses_the_shortest_form() {
        for length in [0_usize, 127, 128, 255, 256] {
            let mut buffer = [0_u8; 16];
            let written = encode(length, &mut buffer).unwrap();

            let expected = if length <= 127 {
                1
            } else if length <= 0xFF {
                2
            } else {
                3
            };
            assert_eq!(written, expected, "length {length}");
        }
    }

    #[test]
    fn the_indefinite_form_decodes_as_a_value_rather_than_an_error() {
        // 解碼寬鬆照 BER，不定長度是合法輸入。
        assert_eq!(decode(&[0x80]).unwrap(), (1, Length::Indefinite));
    }

    #[test]
    fn redundant_length_octets_are_accepted_because_decoding_is_lenient() {
        // 5 寫成長式、還帶前導零 —— 不是 DER，但是合法的 BER。
        assert_eq!(
            decode(&[0x82, 0x00, 0x05]).unwrap(),
            (3, Length::Definite(5))
        );
        assert_eq!(decode(&[0x81, 0x05]).unwrap(), (2, Length::Definite(5)));
    }

    #[test]
    fn the_reserved_first_octet_is_rejected() {
        assert_eq!(decode(&[0xFF]), Err(Asn1Error::MalformedValue));
    }

    #[test]
    fn a_length_beyond_the_platform_word_is_rejected() {
        let mut input = [0xFF_u8; 17];
        input[0] = 0x90; // 長式，16 個長度位元組
        assert_eq!(decode(&input), Err(Asn1Error::LengthOverflow));
    }

    #[test]
    fn a_truncated_length_is_rejected() {
        assert_eq!(decode(&[]), Err(Asn1Error::Truncated));
        assert_eq!(decode(&[0x83, 0x01, 0x02]), Err(Asn1Error::Truncated));
    }

    #[test]
    fn encoding_into_a_short_buffer_is_rejected() {
        assert_eq!(encode(0, &mut []), Err(Asn1Error::BufferTooSmall));
        assert_eq!(encode(300, &mut [0; 2]), Err(Asn1Error::BufferTooSmall));
    }
}
