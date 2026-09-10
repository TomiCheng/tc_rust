//! 識別位元組（identifier octets）的編解碼。
//!
//! 識別位元組的佈局是 `[class:2][constructed:1][number:5]`。號碼 0–30 直接放進
//! 低 5 位；號碼 31 以上時低 5 位全填 1，後面接 base-128 的續接位元組。
//!
//! 解碼寬鬆照 BER，但兩件事**三種規則都禁止**，所以照樣拒絕：低號碼用續接形式
//! 表示（X.690 8.1.2.3），以及續接形式有前導零（8.1.2.4.2c）。

use crate::asn1_error::Asn1Error;

/// 單一識別位元組能容納的最大號碼。
const SHORT_FORM_MAX: u32 = 30;

/// 低 5 位全填 1，表示號碼在後續位元組裡。
const LONG_FORM: u8 = 0x1F;

/// constructed 位。
const CONSTRUCTED: u8 = 0x20;

/// 本實作支援的號碼上限。
///
/// X.690 沒有規定上限，但實務上用到的號碼都很小。限制在 `u32` 讓解碼不必處理
/// 任意長度的號碼，超過就明確回 [`Asn1Error::TagOverflow`]，不會靜靜截斷。
const NUMBER_MAX: u32 = u32::MAX >> 7;

/// tag 的類別，取自識別位元組的最高兩位。
///
/// 變體順序就是 X.690 的類別順序，`Ord` 直接 derive 得到。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Class {
    /// X.680 定義的通用型別。
    Universal,
    /// 應用層自訂。
    Application,
    /// 由所在的結構決定意義，也就是 `[0]`、`[1]` 這種標記。
    ContextSpecific,
    /// 私有用途。
    Private,
}

impl Class {
    /// 類別在識別位元組中的位元樣式。
    const fn bits(self) -> u8 {
        match self {
            Self::Universal => 0x00,
            Self::Application => 0x40,
            Self::ContextSpecific => 0x80,
            Self::Private => 0xC0,
        }
    }

    /// 由識別位元組的最高兩位還原類別。
    const fn from_bits(byte: u8) -> Self {
        match byte & 0xC0 {
            0x00 => Self::Universal,
            0x40 => Self::Application,
            0x80 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }
}

/// 一個 ASN.1 tag。
///
/// # 欄位順序就是排序規則
///
/// `Ord` 是 derive 來的，比較的順序就是欄位宣告的順序：先 `class`、再 `number`、
/// 最後 `constructed`。這正是 DER 的 `SET` 排序要的。
///
/// **不能改成拿識別位元組逐位元組比**，因為 constructed 位夾在 class 和 number
/// 中間：`[0] EXPLICIT SEQUENCE` 是 `A0`，`[1] IMPLICIT INTEGER` 是 `81`，
/// 位元組比較會說 `81` 在前，但 tag 順序是 0 在 1 之前 —— 剛好相反。
///
/// `constructed` 排在最後只是為了讓 `Ord` 與 `Eq` 一致；同一個 `SET` 裡的成員
/// tag 必須相異，所以實際上輪不到它決勝。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Tag {
    class: Class,
    number: u32,
    constructed: bool,
}

impl Tag {
    /// `BOOLEAN`。
    pub const BOOLEAN: Self = Self::universal(1, false);
    /// `INTEGER`。
    pub const INTEGER: Self = Self::universal(2, false);
    /// `BIT STRING`。
    pub const BIT_STRING: Self = Self::universal(3, false);
    /// `OCTET STRING`。
    pub const OCTET_STRING: Self = Self::universal(4, false);
    /// `NULL`。
    pub const NULL: Self = Self::universal(5, false);
    /// `OBJECT IDENTIFIER`。
    pub const OBJECT_IDENTIFIER: Self = Self::universal(6, false);
    /// `ENUMERATED`。
    pub const ENUMERATED: Self = Self::universal(10, false);
    /// `SEQUENCE`，永遠是 constructed。
    pub const SEQUENCE: Self = Self::universal(16, true);
    /// `SET`，永遠是 constructed。
    pub const SET: Self = Self::universal(17, true);

    /// 建立通用類別的 tag。
    const fn universal(number: u32, constructed: bool) -> Self {
        Self {
            class: Class::Universal,
            number,
            constructed,
        }
    }

    /// 建立任意類別的 tag。
    ///
    /// # Panics
    ///
    /// `number` 超過支援上限時 panic。號碼是程式寫死的常數，不是輸入資料，
    /// 所以用 panic 而不是 `Result`；輸入走的是解碼路徑，那裡回錯誤。
    pub const fn new(class: Class, number: u32, constructed: bool) -> Self {
        assert!(
            number <= NUMBER_MAX,
            "tag number exceeds the supported range"
        );
        Self {
            class,
            number,
            constructed,
        }
    }

    /// tag 的類別。
    pub const fn class(self) -> Class {
        self.class
    }

    /// tag 號碼。
    pub const fn number(self) -> u32 {
        self.number
    }

    /// 是否為 constructed，也就是內容由其他 TLV 組成。
    pub const fn is_constructed(self) -> bool {
        self.constructed
    }

    /// 換一個 class 與 number，保留 constructed。
    ///
    /// IMPLICIT tagging 就是這件事：換掉 tag，內容與 constructed 位不變。
    pub const fn retagged(self, class: Class, number: u32) -> Self {
        Self::new(class, number, self.constructed)
    }
}

/// tag 編碼後佔用的位元組數。
pub(crate) const fn encoded_len(tag: Tag) -> usize {
    if tag.number <= SHORT_FORM_MAX {
        return 1;
    }

    // 每個續接位元組帶 7 位。
    let mut bits = 32 - tag.number.leading_zeros();
    let mut length = 1;
    while bits > 0 {
        length += 1;
        bits = bits.saturating_sub(7);
    }
    length
}

/// 變動時間：把 tag 寫進 `buff` 前端，回傳寫入的位元組數。
pub(crate) fn encode(tag: Tag, buff: &mut [u8]) -> Result<usize, Asn1Error> {
    let length = encoded_len(tag);
    let output = buff.get_mut(..length).ok_or(Asn1Error::BufferTooSmall)?;

    let mut first = tag.class.bits();
    if tag.constructed {
        first |= CONSTRUCTED;
    }

    if length == 1 {
        output[0] = first | (tag.number as u8);
        return Ok(1);
    }

    output[0] = first | LONG_FORM;
    // 由最高的 7 位群組往低寫，最後一個位元組的最高位為零。
    for (index, slot) in output[1..].iter_mut().enumerate() {
        let shift = 7 * (length - 2 - index);
        let group = ((tag.number >> shift) & 0x7F) as u8;
        let more = if index + 2 < length { 0x80 } else { 0 };
        *slot = group | more;
    }
    Ok(length)
}

/// 變動時間：由 `buff` 前端解出一個 tag，回傳消耗的位元組數與 tag。
pub(crate) fn decode(buff: &[u8]) -> Result<(usize, Tag), Asn1Error> {
    let (first, rest) = buff.split_first().ok_or(Asn1Error::Truncated)?;
    let class = Class::from_bits(*first);
    let constructed = first & CONSTRUCTED != 0;
    let low = u32::from(first & LONG_FORM);

    if low <= SHORT_FORM_MAX {
        return Ok((
            1,
            Tag {
                class,
                number: low,
                constructed,
            },
        ));
    }

    let mut number: u32 = 0;
    let mut consumed = 1;
    for (index, byte) in rest.iter().enumerate() {
        consumed += 1;

        // 第一個續接位元組是 0x80 表示前導零，三種規則都不允許。
        if index == 0 && *byte == 0x80 {
            return Err(Asn1Error::NonMinimalTag);
        }
        if number > NUMBER_MAX {
            return Err(Asn1Error::TagOverflow);
        }
        number = (number << 7) | u32::from(byte & 0x7F);

        if byte & 0x80 == 0 {
            // 30 以下的號碼必須用單一位元組表示（X.690 8.1.2.3）。
            if number <= SHORT_FORM_MAX {
                return Err(Asn1Error::NonMinimalTag);
            }
            return Ok((
                consumed,
                Tag {
                    class,
                    number,
                    constructed,
                },
            ));
        }
    }

    Err(Asn1Error::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universal_tags_round_trip_through_a_single_byte() {
        for tag in [
            Tag::BOOLEAN,
            Tag::INTEGER,
            Tag::BIT_STRING,
            Tag::OCTET_STRING,
            Tag::NULL,
            Tag::OBJECT_IDENTIFIER,
            Tag::ENUMERATED,
            Tag::SEQUENCE,
            Tag::SET,
        ] {
            let mut buffer = [0_u8; 8];
            let written = encode(tag, &mut buffer).unwrap();
            assert_eq!(written, 1, "{tag:?}");
            assert_eq!(written, encoded_len(tag));

            assert_eq!(decode(&buffer[..written]).unwrap(), (written, tag));
        }
    }

    #[test]
    fn the_universal_constants_carry_the_numbers_x690_assigns() {
        assert_eq!(Tag::BOOLEAN.number(), 1);
        assert_eq!(Tag::NULL.number(), 5);
        assert_eq!(Tag::SEQUENCE.number(), 16);
        assert_eq!(Tag::SET.number(), 17);
        assert!(Tag::SEQUENCE.is_constructed());
        assert!(!Tag::INTEGER.is_constructed());
    }

    #[test]
    fn a_context_specific_constructed_zero_is_the_byte_pkix_uses_everywhere() {
        let tag = Tag::new(Class::ContextSpecific, 0, true);
        let mut buffer = [0_u8; 8];
        encode(tag, &mut buffer).unwrap();

        assert_eq!(buffer[0], 0xA0);
        assert_eq!(decode(&buffer).unwrap().1, tag);
    }

    #[test]
    fn high_numbers_round_trip_across_several_bytes() {
        for number in [31_u32, 127, 128, 16_383, 16_384, 1 << 20] {
            let tag = Tag::new(Class::Application, number, false);
            let mut buffer = [0_u8; 8];
            let written = encode(tag, &mut buffer).unwrap();

            assert!(written > 1, "number {number} should need the long form");
            assert_eq!(written, encoded_len(tag));
            assert_eq!(decode(&buffer[..written]).unwrap(), (written, tag));
        }
    }

    #[test]
    fn retagging_keeps_the_constructed_bit() {
        // IMPLICIT tagging 換掉 tag，但 constructed 位由被標記的型別決定。
        let implicit = Tag::SEQUENCE.retagged(Class::ContextSpecific, 0);
        assert!(implicit.is_constructed());
        assert_eq!(implicit.class(), Class::ContextSpecific);
        assert_eq!(implicit.number(), 0);

        let implicit = Tag::INTEGER.retagged(Class::ContextSpecific, 0);
        assert!(!implicit.is_constructed());
    }

    #[test]
    fn ordering_follows_class_and_number_not_the_identifier_byte() {
        // [0] EXPLICIT SEQUENCE 是 0xA0，[1] IMPLICIT INTEGER 是 0x81。
        // 位元組比較會說 0x81 在前，但 tag 順序是 0 在 1 之前。
        let zero = Tag::new(Class::ContextSpecific, 0, true);
        let one = Tag::new(Class::ContextSpecific, 1, false);

        let mut zero_byte = [0_u8; 2];
        let mut one_byte = [0_u8; 2];
        encode(zero, &mut zero_byte).unwrap();
        encode(one, &mut one_byte).unwrap();

        assert!(one_byte[0] < zero_byte[0], "位元組比較的方向");
        assert!(zero < one, "tag 順序的方向");
    }

    #[test]
    fn classes_sort_in_the_order_x690_gives_them() {
        assert!(Class::Universal < Class::Application);
        assert!(Class::Application < Class::ContextSpecific);
        assert!(Class::ContextSpecific < Class::Private);
    }

    #[test]
    fn a_low_number_written_in_the_long_form_is_rejected() {
        // 號碼 5 應該寫成單一位元組，不是 0x1F 0x05。
        assert_eq!(decode(&[0x1F, 0x05]), Err(Asn1Error::NonMinimalTag));
    }

    #[test]
    fn a_leading_zero_group_is_rejected() {
        assert_eq!(decode(&[0x1F, 0x80, 0x7F]), Err(Asn1Error::NonMinimalTag));
    }

    #[test]
    fn a_number_beyond_the_supported_range_is_rejected() {
        // 六個滿載的續接位元組遠超過 u32。
        assert_eq!(
            decode(&[0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
            Err(Asn1Error::TagOverflow)
        );
    }

    #[test]
    fn a_truncated_tag_is_rejected() {
        assert_eq!(decode(&[]), Err(Asn1Error::Truncated));
        // 最高位表示還有續接位元組，但輸入結束了。
        assert_eq!(decode(&[0x1F, 0x81]), Err(Asn1Error::Truncated));
    }

    #[test]
    fn encoding_into_a_short_buffer_is_rejected() {
        assert_eq!(
            encode(Tag::INTEGER, &mut []),
            Err(Asn1Error::BufferTooSmall)
        );
        let tag = Tag::new(Class::Application, 1 << 20, false);
        assert_eq!(encode(tag, &mut [0; 2]), Err(Asn1Error::BufferTooSmall));
    }
}
