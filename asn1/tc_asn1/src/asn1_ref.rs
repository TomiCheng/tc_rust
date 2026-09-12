//! 借用輸入位元組的一個 TLV。

use crate::decoding_options::DecodingOptions;
use crate::error::Asn1Error;
use crate::traits::{Decode, DecodeConstructed};

/// tag 的類別，取自識別位元組的最高兩位。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Asn1Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl Asn1Class {
    pub(crate) fn of(first: u8) -> Self {
        match first >> 6 {
            0 => Self::Universal,
            1 => Self::Application,
            2 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Asn1Ref<'a> {
    /// 整段 TLV，含表頭；不定長時含 EOC。
    raw: &'a [u8],
    tag: &'a [u8],
    value: &'a [u8],
}

impl<'a> Asn1Ref<'a> {
    pub(crate) fn from_validated_parts(
        raw: &'a [u8],
        tag_len: usize,
        value_offset: usize,
        value_len: usize,
    ) -> Self {
        Self {
            raw,
            tag: &raw[..tag_len],
            value: &raw[value_offset..value_offset + value_len],
        }
    }

    /// Parse the first TLV with the supplied decoding limits.
    /// Definite-length contents stay borrowed; their children are checked when
    /// traversed. Indefinite lengths require traversal to locate the closing EOC.
    /// Variable time: public values only; no constant-time alternative is provided.
    pub fn parse(buff: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        let tag = parse_tag(buff)?;
        let (len_len, length) = parse_len(&buff[tag.len()..])?;
        let offset = tag.len() + len_len;

        match length {
            Some(n) => {
                let end = offset.checked_add(n).ok_or(Asn1Error::LengthOverflow)?;
                options.check_content_len(n)?;
                let value = buff.get(offset..end).ok_or(Asn1Error::Truncated)?;
                Ok(Self {
                    raw: &buff[..end],
                    tag,
                    value,
                })
            }
            None => {
                // 不定長只允許 constructed；內容是一串 TLV，讀到 00 00 為止。
                if tag[0] & 0x20 == 0 {
                    return Err(Asn1Error::MalformedValue);
                }
                let options = options.descend()?;
                let mut at = offset;
                let mut count = 0;
                loop {
                    let rest = buff.get(at..).ok_or(Asn1Error::Truncated)?;
                    if rest.len() < 2 {
                        return Err(Asn1Error::Truncated);
                    }
                    if rest[..2] == [0x00, 0x00] {
                        break;
                    }
                    if count == options.max_children() {
                        return Err(Asn1Error::ChildrenExceeded);
                    }
                    at += Self::parse(rest, options)?.total_len(); // 整個子 TLV 跳過
                    count += 1;
                    options.check_content_len(at - offset)?;
                }
                Ok(Self {
                    raw: &buff[..at + 2],
                    tag,
                    value: &buff[offset..at],
                })
            }
        }
    }

    /// 整段 TLV，含表頭。把子元素當另一個型別 `try_decode` 時用它。
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn tag(&self) -> &'a [u8] {
        self.tag
    }

    pub fn class(&self) -> Asn1Class {
        Asn1Class::of(self.tag[0])
    }

    pub fn is_constructed(&self) -> bool {
        self.tag[0] & 0x20 != 0
    }

    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    pub fn total_len(&self) -> usize {
        self.raw.len()
    }

    /// 走訪子元素。primitive 沒有子元素，回空的迭代器。
    pub fn children(&self, options: DecodingOptions) -> Children<'a> {
        Children::new(
            if self.is_constructed() {
                self.value
            } else {
                &[]
            },
            options,
        )
    }

    /// Decode this complete element as the type selected by the caller's schema.
    /// The schema validates the identifier; this method requires full consumption
    /// of this element. Variable time: public values only; no constant-time alternative.
    pub fn decode_as<T: Decode<'a>>(&self, options: DecodingOptions) -> Result<T, Asn1Error> {
        let (used, value) = T::try_decode(self.raw, options)?;
        if used != self.total_len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }

    /// Decode constructed string contents as the type selected by the schema.
    /// Checks the constructed bit; the caller validates the tag class and number.
    /// 變動時間：分支只依編碼結構，只能用於公開值；沒有常數時間替代方法。
    pub fn decode_constructed_as<T>(&self, options: DecodingOptions) -> Result<T, Asn1Error>
    where
        T: DecodeConstructed<'a>,
    {
        if !self.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        options.check_content_len(self.value.len())?;
        <T as DecodeConstructed<'a>>::try_decode_constructed(self.value, options)
    }
}

/// 同長度、首位元組只多 constructed 位，且原標記本身為 primitive。
pub(crate) fn is_constructed_form(tag: &[u8], primitive_tag: &[u8]) -> bool {
    !primitive_tag.is_empty()
        && tag.len() == primitive_tag.len()
        && primitive_tag[0] & 0x20 == 0
        && tag[0] == primitive_tag[0] | 0x20
        && tag[1..] == primitive_tag[1..]
}

pub struct Children<'a> {
    rest: &'a [u8],
    options: DecodingOptions,
    remaining: usize,
    oversized: bool,
}

impl<'a> Children<'a> {
    /// 從一段內容位元組開始走訪 —— constructed 型別的 `try_decode_content` 用這個。
    pub fn new(rest: &'a [u8], options: DecodingOptions) -> Self {
        Self {
            rest,
            options,
            remaining: options.max_children(),
            oversized: rest.len() > options.max_content_len(),
        }
    }
}

impl<'a> Iterator for Children<'a> {
    type Item = Result<Asn1Ref<'a>, Asn1Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        if self.oversized || self.remaining == 0 {
            self.rest = &[];
            return Some(Err(if self.oversized {
                Asn1Error::ContentLengthExceeded
            } else {
                Asn1Error::ChildrenExceeded
            }));
        }
        match Asn1Ref::parse(self.rest, self.options) {
            Ok(child) => {
                self.remaining -= 1;
                self.rest = &self.rest[child.total_len()..];
                Some(Ok(child))
            }
            Err(error) => {
                self.rest = &[]; // 出錯就停，不重複回報
                Some(Err(error))
            }
        }
    }
}

/// 由 `buff` 前端切出識別位元組，不解析號碼。
pub(crate) fn parse_tag(buff: &[u8]) -> Result<&[u8], Asn1Error> {
    let first = *buff.first().ok_or(Asn1Error::Truncated)?;
    if first & 0x1F != 0x1F {
        return Ok(&buff[..1]);
    }

    // 高號碼形式：每個續接位元組帶 7 位，最高位為 1 表示還有下一個。
    for (index, byte) in buff[1..].iter().enumerate() {
        if index == 0 && *byte == 0x80 {
            return Err(Asn1Error::NonMinimalTag); // 前導零
        }
        if byte & 0x80 == 0 {
            if index == 0 && *byte <= 30 {
                return Err(Asn1Error::NonMinimalTag); // 30 以下必須用短式
            }
            return Ok(&buff[..index + 2]);
        }
    }
    Err(Asn1Error::Truncated)
}

/// 由 `buff` 前端解出長度欄位，回傳它佔的位元組數與內容長度；不定長為 `None`。
fn parse_len(buff: &[u8]) -> Result<(usize, Option<usize>), Asn1Error> {
    let (first, rest) = buff.split_first().ok_or(Asn1Error::Truncated)?;
    match *first {
        0x00..=0x7F => Ok((1, Some(usize::from(*first)))),
        0x80 => Ok((1, None)),
        0xFF => Err(Asn1Error::MalformedValue), // X.690 保留
        _ => {
            let count = usize::from(first & 0x7F);
            let octets = rest.get(..count).ok_or(Asn1Error::Truncated)?;
            let mut length: usize = 0;
            for byte in octets {
                // checked_mul 而不是 checked_shl：後者不檢查移掉的高位。
                length = length
                    .checked_mul(256)
                    .and_then(|shifted| shifted.checked_add(usize::from(*byte)))
                    .ok_or(Asn1Error::LengthOverflow)?;
            }
            Ok((1 + count, Some(length)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    fn parse(bytes: &[u8]) -> Asn1Ref<'_> {
        Asn1Ref::parse(bytes, OPTIONS).unwrap()
    }

    // ---- parse_tag

    #[test]
    fn a_low_number_tag_is_one_byte_and_a_high_number_tag_keeps_all_of_its_bytes() {
        assert_eq!(parse_tag(&[0x05, 0x00]).unwrap(), &[0x05]);
        assert_eq!(parse_tag(&[0x1F, 0x1F]).unwrap(), &[0x1F, 0x1F]); // 31
        assert_eq!(
            parse_tag(&[0x1F, 0x81, 0x00, 0xAA]).unwrap(),
            &[0x1F, 0x81, 0x00]
        ); // 128
    }

    #[test]
    fn non_minimal_tag_encodings_are_rejected_even_under_ber() {
        assert_eq!(parse_tag(&[0x1F, 0x05]), Err(Asn1Error::NonMinimalTag)); // 5 用長式
        assert_eq!(
            parse_tag(&[0x1F, 0x80, 0x7F]),
            Err(Asn1Error::NonMinimalTag)
        ); // 前導零
    }

    #[test]
    fn a_truncated_tag_is_rejected() {
        assert_eq!(parse_tag(&[]), Err(Asn1Error::Truncated));
        assert_eq!(parse_tag(&[0x1F, 0x81]), Err(Asn1Error::Truncated));
    }

    // ---- parse_len

    #[test]
    fn short_long_and_indefinite_length_forms_are_told_apart() {
        assert_eq!(parse_len(&[0x05]).unwrap(), (1, Some(5)));
        assert_eq!(parse_len(&[0x7F]).unwrap(), (1, Some(127)));
        assert_eq!(parse_len(&[0x81, 0x80]).unwrap(), (2, Some(128)));
        assert_eq!(parse_len(&[0x82, 0x03, 0xE8]).unwrap(), (3, Some(1000)));
        assert_eq!(parse_len(&[0x80]).unwrap(), (1, None));
    }

    #[test]
    fn redundant_length_octets_are_accepted_because_decoding_is_lenient() {
        assert_eq!(parse_len(&[0x81, 0x05]).unwrap(), (2, Some(5)));
        assert_eq!(parse_len(&[0x82, 0x00, 0x05]).unwrap(), (3, Some(5)));
    }

    #[test]
    fn bad_length_octets_are_rejected() {
        assert_eq!(parse_len(&[]), Err(Asn1Error::Truncated));
        assert_eq!(parse_len(&[0x83, 0x01, 0x02]), Err(Asn1Error::Truncated));
        assert_eq!(parse_len(&[0xFF]), Err(Asn1Error::MalformedValue));

        let mut huge = [0xFF_u8; 17];
        huge[0] = 0x90; // 16 個長度位元組
        assert_eq!(parse_len(&huge), Err(Asn1Error::LengthOverflow));
    }

    // ---- Asn1Ref::parse，定長

    #[test]
    fn a_definite_length_tlv_yields_its_value_and_its_total_size() {
        let element = parse(&[0x02, 0x01, 0x05, 0xAA]); // INTEGER 5，後面還有東西

        assert_eq!(element.tag(), &[0x02]);
        assert_eq!(element.value(), &[0x05]);
        assert_eq!(element.total_len(), 3, "不含後面的 0xAA");
    }

    #[test]
    fn raw_is_the_whole_tlv_and_value_sits_inside_it() {
        let element = parse(&[0x02, 0x01, 0x05, 0xAA]);
        assert_eq!(element.raw(), &[0x02, 0x01, 0x05]);

        // 不定長：raw 含 EOC，value 不含
        let element = parse(&[0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0xAA]);
        assert_eq!(element.raw(), &[0x30, 0x80, 0x05, 0x00, 0x00, 0x00]);
        assert_eq!(element.value(), &[0x05, 0x00]);
    }

    #[test]
    fn a_length_promising_more_than_the_input_holds_is_rejected() {
        assert_eq!(
            Asn1Ref::parse(&[0x04, 0x05, 0x01, 0x02], OPTIONS).err(),
            Some(Asn1Error::Truncated)
        );
    }

    #[test]
    fn a_length_that_overflows_when_added_to_the_header_is_rejected() {
        // 長度剛好 usize::MAX，加上表頭就溢位。
        let mut input = [0xFF_u8; 10];
        input[0] = 0x04;
        input[1] = 0x88; // 8 個長度位元組
        assert_eq!(
            Asn1Ref::parse(&input, OPTIONS).err(),
            Some(Asn1Error::LengthOverflow)
        );
    }

    // ---- Asn1Ref::parse，不定長

    #[test]
    fn an_indefinite_length_value_stops_at_the_end_of_contents_marker() {
        // 30 80  05 00  00 00  02 01 05
        let input = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x02, 0x01, 0x05];
        let element = parse(&input);

        assert_eq!(element.value(), &[0x05, 0x00], "不含 EOC");
        assert_eq!(element.total_len(), 6, "含 EOC，不含後面的 sibling");
        assert_eq!(&input[element.total_len()..], &[0x02, 0x01, 0x05]);
    }

    #[test]
    fn the_end_of_contents_marker_is_only_recognised_at_a_tlv_boundary() {
        // 31 80  31 03 01 01 00  00 00
        //                    ^^^^^ 相鄰的兩個 00 跨在成員內容與 EOC 之間。
        //                          掃描 00 00 會在這裡誤命中，照邊界走才會落在正確的位置。
        let input = [0x31, 0x80, 0x31, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(&input[6..8], &[0x00, 0x00], "誤命中的位置確實存在");

        let element = parse(&input);
        assert_eq!(element.total_len(), input.len());
        assert_eq!(
            element.value(),
            &[0x31, 0x03, 0x01, 0x01, 0x00],
            "內部的 SET 沒有被腰斬"
        );
    }

    #[test]
    fn nested_indefinite_lengths_each_find_their_own_marker() {
        // 30 80  30 80  05 00  00 00  00 00
        let input = [0x30, 0x80, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let outer = parse(&input);

        assert_eq!(outer.total_len(), input.len());
        assert_eq!(outer.value(), &[0x30, 0x80, 0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn an_indefinite_length_without_its_marker_is_rejected() {
        assert_eq!(
            Asn1Ref::parse(&[0x30, 0x80, 0x05, 0x00], OPTIONS).err(),
            Some(Asn1Error::Truncated)
        );
    }

    #[test]
    fn an_indefinite_length_on_a_primitive_tag_is_rejected() {
        assert_eq!(
            Asn1Ref::parse(&[0x04, 0x80, 0x00, 0x00], OPTIONS).err(),
            Some(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn indefinite_nesting_deeper_than_the_budget_is_rejected() {
        // 八層 30 80，中間一個 05 00，然後八個 00 00。只有不定長會在 parse 裡遞迴。
        let levels = 8;
        let mut bytes = [0_u8; 64];
        let mut at = 0;
        for _ in 0..levels {
            bytes[at] = 0x30;
            bytes[at + 1] = 0x80;
            at += 2;
        }
        bytes[at] = 0x05;
        at += 2 + 2 * levels; // 05 00，然後 EOC 都是零
        let input = &bytes[..at];

        assert!(
            Asn1Ref::parse(
                input,
                DecodingOptions::new(crate::Depth::new(16), 16 * 1024 * 1024, 65_536)
            )
            .is_ok()
        );
        assert_eq!(
            Asn1Ref::parse(
                input,
                DecodingOptions::new(crate::Depth::new(4), 16 * 1024 * 1024, 65_536)
            )
            .err(),
            Some(Asn1Error::DepthExceeded)
        );
    }

    // ---- accessors

    #[test]
    fn class_and_constructed_come_from_the_identifier_byte() {
        assert_eq!(parse(&[0x05, 0x00]).class(), Asn1Class::Universal);
        assert_eq!(parse(&[0x45, 0x00]).class(), Asn1Class::Application);
        assert_eq!(parse(&[0x85, 0x00]).class(), Asn1Class::ContextSpecific);
        assert_eq!(parse(&[0xC5, 0x00]).class(), Asn1Class::Private);

        assert!(!parse(&[0x05, 0x00]).is_constructed());
        assert!(parse(&[0x30, 0x00]).is_constructed());
        assert!(parse(&[0xA0, 0x00]).is_constructed());
        assert!(
            parse(&[0x30, 0x00]).class() == Asn1Class::Universal,
            "建構位不影響類別"
        );
    }

    // ---- children

    #[test]
    fn children_walk_a_constructed_value_exactly_once_each() {
        // 30 06  05 00  02 01 05
        let seq = parse(&[0x30, 0x05, 0x05, 0x00, 0x02, 0x01, 0x05]);
        let mut tags = [0_u8; 4];
        let mut count = 0;

        for child in seq.children(OPTIONS) {
            tags[count] = child.unwrap().tag()[0];
            count += 1;
        }

        assert_eq!(count, 2);
        assert_eq!(&tags[..2], &[0x05, 0x02]);
    }

    #[test]
    fn a_primitive_has_no_children() {
        assert_eq!(parse(&[0x02, 0x01, 0x05]).children(OPTIONS).count(), 0);
    }

    #[test]
    fn a_broken_child_is_reported_once_and_then_iteration_stops() {
        // 30 04  05 00  02 05     ← 第二個子元素說有 5 個位元組，沒有
        let seq = parse(&[0x30, 0x04, 0x05, 0x00, 0x02, 0x05]);
        let mut children = seq.children(OPTIONS);

        assert!(children.next().unwrap().is_ok());
        assert_eq!(children.next().unwrap().err(), Some(Asn1Error::Truncated));
        assert!(children.next().is_none(), "出錯之後不再產生任何東西");
    }

    #[test]
    fn children_of_an_indefinite_length_value_do_not_include_the_marker() {
        let seq = parse(&[0x30, 0x80, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00]);
        assert_eq!(seq.children(OPTIONS).count(), 2);
    }
    #[test]
    fn constructed_form_matching_changes_only_the_constructed_bit_of_a_complete_identifier() {
        assert!(is_constructed_form(&[0x24], &[4]));
        assert!(is_constructed_form(&[0xbf, 0x81, 0], &[0x9f, 0x81, 0]));
        for (tag, primitive) in [
            (&[][..], &[][..]),
            (&[0x24][..], &[][..]),
            (&[][..], &[4][..]),
            (&[0x24][..], &[0x24][..]),
            (&[4][..], &[4][..]),
            (&[0x64][..], &[4][..]),
            (&[0x24, 0][..], &[4][..]),
            (&[0xbf, 0x81, 1][..], &[0x9f, 0x81, 0][..]),
        ] {
            assert!(!is_constructed_form(tag, primitive));
        }
    }
}
