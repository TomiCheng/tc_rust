//! ASN.1 `SET`。

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::asn1_error::Asn1Error;
use crate::asn1_object::Asn1Object;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::length::{self, Length};
use crate::tag::{self, Tag};
use crate::traits::{TryDecode, TryEncode};

/// 一個 ASN.1 `SET`。
///
/// # 順序
///
/// 成員照放進來的順序存著，**排序發生在寫出的時候**，而且只有
/// [`EncodingType::Der`] 會排。這樣 BER 與 DL 保得住原順序，解出來的值也不必
/// 記得自己被排過。
///
/// DER 的順序是 tag、內容長度、內容位元組（X.690 11.6）。**不是拿完整編碼逐
/// 位元組比** —— constructed 位夾在 class 與 number 中間，那樣會排錯，詳見
/// [`Tag`]。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Set {
    contents: Vec<Asn1Object>,
}

/// 一個成員編好的樣子，連同排序要用的鍵。
struct Member {
    tag: Tag,
    encoded: Vec<u8>,
    contents_at: usize,
}

impl Member {
    /// 內容位元組，不含 tag 與長度。
    fn contents(&self) -> &[u8] {
        &self.encoded[self.contents_at..]
    }

    /// X.690 11.6 的順序。
    fn compare(&self, other: &Self) -> Ordering {
        self.tag
            .cmp(&other.tag)
            .then_with(|| self.contents().len().cmp(&other.contents().len()))
            .then_with(|| self.contents().cmp(other.contents()))
    }
}

impl Asn1Set {
    /// 建立一個 `SET`。成員照給定的順序存著。
    pub const fn new(contents: Vec<Asn1Object>) -> Self {
        Self { contents }
    }

    /// 成員，照存放的順序。
    pub fn contents(&self) -> &[Asn1Object] {
        &self.contents
    }

    /// 內容位元組數，也就是所有成員編碼串起來的長度。
    fn contents_len(&self, encoding_type: EncodingType) -> Result<usize, Asn1Error> {
        let mut total: usize = 0;
        for member in &self.contents {
            total = total
                .checked_add(member.try_encode_len(encoding_type)?)
                .ok_or(Asn1Error::LengthOverflow)?;
        }
        Ok(total)
    }

    /// 表頭佔用的位元組數。
    fn header_len(contents_len: usize) -> usize {
        tag::encoded_len(Tag::SET) + length::encoded_len(contents_len)
    }

    /// 把成員各自編好，供排序用。
    fn encoded_members(&self, encoding_type: EncodingType) -> Result<Vec<Member>, Asn1Error> {
        let mut members = Vec::with_capacity(self.contents.len());

        for object in &self.contents {
            let mut encoded = vec![0_u8; object.try_encode_len(encoding_type)?];
            object.try_encode(encoding_type, &mut encoded)?;

            let object_tag = object.tag();
            let tag_len = tag::encoded_len(object_tag);
            let (length_len, _) = length::decode(&encoded[tag_len..])?;

            members.push(Member {
                tag: object_tag,
                encoded,
                contents_at: tag_len + length_len,
            });
        }

        Ok(members)
    }
}

impl TryEncode for Asn1Set {
    type Error = Asn1Error;

    /// 變動時間：表頭加上所有成員的長度。排序不改變總長，所以這裡不排。
    fn try_encode_len(&self, encoding_type: EncodingType) -> Result<usize, Self::Error> {
        let contents_len = self.contents_len(encoding_type)?;

        Self::header_len(contents_len)
            .checked_add(contents_len)
            .ok_or(Asn1Error::LengthOverflow)
    }

    /// 變動時間：寫出 `SET`。長度一律用定長形式。
    ///
    /// BER 允許不定長度，但寫出時長度已經算得出來，沒有理由用它。解碼側仍然
    /// 接受不定長度的輸入。
    fn try_encode(
        &self,
        encoding_type: EncodingType,
        buff: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let contents_len = self.contents_len(encoding_type)?;
        let total = self.try_encode_len(encoding_type)?;
        let output = buff.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;

        let mut at = tag::encode(Tag::SET, output)?;
        at += length::encode(contents_len, &mut output[at..])?;

        if encoding_type == EncodingType::Der {
            let mut members = self.encoded_members(encoding_type)?;
            members.sort_by(Member::compare);

            for member in &members {
                output[at..at + member.encoded.len()].copy_from_slice(&member.encoded);
                at += member.encoded.len();
            }
        } else {
            for object in &self.contents {
                at += object.try_encode(encoding_type, &mut output[at..])?;
            }
        }

        Ok(total)
    }
}

impl TryDecode for Asn1Set {
    type Error = Asn1Error;

    /// 變動時間：分支只依編碼結構。
    ///
    /// 定長與不定長（BER）都接受。成員順序原樣保留 —— DER 要求排序這件事由
    /// 往返比較判定，不在這裡拒絕。
    fn try_decode(buff: &[u8], depth: Depth) -> Result<(usize, Self), Self::Error> {
        let (tag_len, decoded_tag) = tag::decode(buff)?;
        if decoded_tag != Tag::SET {
            return Err(Asn1Error::UnexpectedTag);
        }

        let (length_len, length) = length::decode(&buff[tag_len..])?;
        let body = &buff[tag_len + length_len..];

        match length {
            Length::Definite(contents_len) => {
                let contents = body.get(..contents_len).ok_or(Asn1Error::Truncated)?;
                let members = decode_members(contents, depth)?;

                Ok((tag_len + length_len + contents_len, Self::new(members)))
            }
            Length::Indefinite => {
                let (consumed, members) = decode_until_end_of_contents(body, depth)?;

                Ok((tag_len + length_len + consumed, Self::new(members)))
            }
        }
    }
}

/// 把一段內容位元組解成一串成員，要求剛好用完。
fn decode_members(contents: &[u8], depth: Depth) -> Result<Vec<Asn1Object>, Asn1Error> {
    let mut members = Vec::new();
    let mut at = 0;

    while at < contents.len() {
        let (consumed, member) = Asn1Object::try_decode(&contents[at..], depth)?;
        at += consumed;
        members.push(member);
    }

    Ok(members)
}

/// 不定長度：一直讀到 end-of-contents 標記，回傳連標記一起消耗的位元組數。
fn decode_until_end_of_contents(
    body: &[u8],
    depth: Depth,
) -> Result<(usize, Vec<Asn1Object>), Asn1Error> {
    let mut members = Vec::new();
    let mut at = 0;

    loop {
        let remaining = body.get(at..).ok_or(Asn1Error::Truncated)?;
        if remaining.len() < length::END_OF_CONTENTS.len() {
            return Err(Asn1Error::Truncated);
        }
        if remaining.starts_with(&length::END_OF_CONTENTS) {
            return Ok((at + length::END_OF_CONTENTS.len(), members));
        }

        let (consumed, member) = Asn1Object::try_decode(remaining, depth)?;
        at += consumed;
        members.push(member);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_object::asn1_boolean::Asn1Boolean;
    use crate::asn1_object::asn1_null::Asn1Null;

    const DEPTH: Depth = Depth::DEFAULT;
    const RULES: [EncodingType; 3] = [EncodingType::Ber, EncodingType::Dl, EncodingType::Der];

    fn boolean(value: bool) -> Asn1Object {
        Asn1Object::Boolean(Asn1Boolean::new(value))
    }

    fn encode(set: &Asn1Set, rule: EncodingType) -> Vec<u8> {
        let mut buffer = vec![0_u8; set.try_encode_len(rule).unwrap()];
        let written = set.try_encode(rule, &mut buffer).unwrap();

        assert_eq!(written, buffer.len(), "寫出的長度要等於回報的長度");
        buffer
    }

    #[test]
    fn an_empty_set_is_a_tag_and_a_zero_length() {
        for rule in RULES {
            assert_eq!(encode(&Asn1Set::new(Vec::new()), rule), [0x31, 0x00]);
        }
    }

    #[test]
    fn members_are_written_between_the_header_and_nothing_else() {
        let set = Asn1Set::new(vec![Asn1Object::Null(Asn1Null)]);

        assert_eq!(encode(&set, EncodingType::Der), [0x31, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn der_sorts_members_but_the_other_rules_keep_the_given_order() {
        // NULL 的 tag 是 5，BOOLEAN 是 1 —— 放進去時故意顛倒。
        let set = Asn1Set::new(vec![Asn1Object::Null(Asn1Null), boolean(true)]);

        assert_eq!(
            encode(&set, EncodingType::Der),
            [0x31, 0x05, 0x01, 0x01, 0xFF, 0x05, 0x00],
            "DER 應該把 BOOLEAN 排到前面"
        );
        for rule in [EncodingType::Ber, EncodingType::Dl] {
            assert_eq!(
                encode(&set, rule),
                [0x31, 0x05, 0x05, 0x00, 0x01, 0x01, 0xFF],
                "{rule:?} 應該保留原順序"
            );
        }
    }

    #[test]
    fn sorting_orders_equal_tags_by_contents() {
        let set = Asn1Set::new(vec![boolean(true), boolean(false)]);

        // 內容長度相同，所以比內容位元組：0x00 在 0xFF 之前。
        assert_eq!(
            encode(&set, EncodingType::Der),
            [0x31, 0x06, 0x01, 0x01, 0x00, 0x01, 0x01, 0xFF]
        );
    }

    #[test]
    fn a_set_survives_a_round_trip() {
        let set = Asn1Set::new(vec![boolean(true), Asn1Object::Null(Asn1Null)]);
        let encoded = encode(&set, EncodingType::Der);

        let (consumed, decoded) = Asn1Set::try_decode(&encoded, DEPTH).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.contents().len(), 2);
        assert_eq!(decoded.contents()[0].tag(), Tag::BOOLEAN);
        assert_eq!(decoded.contents()[1].tag(), Tag::NULL);
    }

    #[test]
    fn an_indefinite_length_set_decodes_up_to_the_end_of_contents_marker() {
        let input = [0x31, 0x80, 0x05, 0x00, 0x00, 0x00];
        let (consumed, decoded) = Asn1Set::try_decode(&input, DEPTH).unwrap();

        assert_eq!(consumed, input.len());
        assert_eq!(decoded.contents().len(), 1);
    }

    #[test]
    fn an_indefinite_length_set_without_its_marker_is_rejected() {
        assert_eq!(
            Asn1Set::try_decode(&[0x31, 0x80, 0x05, 0x00], DEPTH),
            Err(Asn1Error::Truncated)
        );
    }

    #[test]
    fn nesting_deeper_than_the_budget_is_rejected() {
        // 每一層都是一個裝著下一層的 SET。
        let mut input = vec![0x05, 0x00];
        for _ in 0..8 {
            let mut wrapper = vec![0x31, input.len() as u8];
            wrapper.extend_from_slice(&input);
            input = wrapper;
        }

        assert!(Asn1Set::try_decode(&input, Depth::new(16)).is_ok());
        assert_eq!(
            Asn1Set::try_decode(&input, Depth::new(4)),
            Err(Asn1Error::DepthExceeded)
        );
    }

    #[test]
    fn a_tag_other_than_set_is_rejected() {
        assert_eq!(
            Asn1Set::try_decode(&[0x30, 0x00], DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn contents_shorter_than_the_length_promises_are_rejected() {
        assert_eq!(
            Asn1Set::try_decode(&[0x31, 0x04, 0x05, 0x00], DEPTH),
            Err(Asn1Error::Truncated)
        );
    }

    #[test]
    fn a_buffer_shorter_than_the_encoding_is_rejected() {
        let set = Asn1Set::new(vec![boolean(true)]);

        assert_eq!(
            set.try_encode(EncodingType::Der, &mut [0; 3]),
            Err(Asn1Error::BufferTooSmall)
        );
    }
}
