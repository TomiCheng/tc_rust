//! ASN.1 SET OF，採用 X.690 §11.6 的完整編碼排序。
//!
//! Bouncy Castle 的 `DerSet` 共用一套先比標籤、再遞迴比較子元素的規則。
//! 這裡以標準為準，不承諾 `SET OF` 與它產生相同位元組。例如 `SET OF CHOICE`
//! 的選項若有不同的 constructed 位，標籤號碼順序可能與完整編碼順序相反。
//! 一般 RDN 的直接成員都是 `SEQUENCE`，不會遇到這個直接成員標籤的反例。

use alloc::vec;
use alloc::vec::Vec;

use crate::asn1_ref::Children;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

use super::tag::SET as TAG;

/// 同型別的 `SET OF`；保留加入或解碼的順序，只有 DER 輸出會排序。
///
/// X.690 §11.6 比較成員的完整 DER 編碼，採位元組字典序。條文的尾端補零
/// 對合法的完整 TLV 不影響結果：一個 TLV 不會是另一個的真前綴，表頭的
/// 標籤或長度必定先有差異。成員本身必須能產生 DER；[`crate::Asn1Any`]
/// 只會原樣重送，排序不會替它正規化內容。
///
/// # Examples
///
/// DER 排序不會改動儲存的順序。
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1SetOf, Encode, EncodingType};
///
/// let values = Asn1SetOf::from(vec![Asn1Boolean(true), Asn1Boolean(false)]);
/// let mut out = [0; 8];
/// values.encode(EncodingType::Der, &mut out).unwrap();
/// assert_eq!(out, [0x31, 6, 1, 1, 0, 1, 1, 0xFF]);
/// assert_eq!(values.members()[0], Asn1Boolean(true));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1SetOf<T> {
    members: Vec<T>,
}

impl<T> Asn1SetOf<T> {
    /// 建立空集合。
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// 在尾端加入成員，不排序。
    pub fn push(&mut self, member: T) {
        self.members.push(member);
    }

    /// 借用原順序的成員。
    pub fn members(&self) -> &[T] {
        &self.members
    }

    /// 回傳成員數。
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// 判斷是否沒有成員。
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

impl<T> Default for Asn1SetOf<T> {
    /// 建立空集合。
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<T>> for Asn1SetOf<T> {
    /// 接收成員並保留順序。
    fn from(members: Vec<T>) -> Self {
        Self { members }
    }
}

impl<T> FromIterator<T> for Asn1SetOf<T> {
    /// 收集成員並保留順序。
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            members: iter.into_iter().collect(),
        }
    }
}

impl<'a, T: TryDecodeContent<'a>> TryDecodeContent<'a> for Asn1SetOf<T> {
    const TAG: &'static [u8] = TAG;

    /// 逐一解碼並保留輸入順序，不排序也不驗序；任何成員失敗便整體失敗。
    /// 變動時間：分支只依編碼結構。
    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        let members = Children::new(value, depth)
            .map(|child| child?.decode_as::<T>(depth))
            .collect::<Result<Vec<T>, _>>()?;
        Ok(Self { members })
    }
}

impl<T: Encode> Encode for Asn1SetOf<T> {
    /// 回傳集合標籤。
    fn tag(&self) -> &[u8] {
        TAG
    }

    /// 加總成員的完整編碼長度，排序不影響長度。
    /// 變動時間：分支只依編碼結構。
    fn content_len(&self, rules: EncodingType) -> usize {
        self.members
            .iter()
            .map(|member| member.encoded_len(rules))
            .sum()
    }

    /// BER 按原順序寫入；DER 暫存每個成員的完整編碼，再依位元組字典序寫入。
    /// 變動時間：依編碼結構分支，DER 排序另比較成員的編碼位元組。
    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        if rules == EncodingType::Ber {
            let mut at = 0;
            for member in &self.members {
                at += member.encode(rules, &mut out[at..])?;
            }
            return Ok(at);
        }

        let mut encodings = self
            .members
            .iter()
            .map(|member| encode_member(member, rules))
            .collect::<Result<Vec<_>, _>>()?;
        encodings.sort();
        copy_encodings(encodings.iter().map(Vec::as_slice), out)
    }
}

// 標籤須為合法的識別位元組；解析器保留任意長度，排序鍵另限制為 u64。
pub(crate) fn tag_key(tag: &[u8]) -> Result<(u8, u64), Asn1Error> {
    if tag.is_empty() {
        return Err(Asn1Error::MalformedValue);
    }
    if tag.len() > 11 || (tag.len() == 11 && tag[1] & 0x7F > 1) {
        return Err(Asn1Error::TagOverflow);
    }
    let class = tag[0] >> 6;
    let mut number = u64::from(tag[0] & 0x1F);
    if number == 0x1F {
        number = 0;
        for byte in &tag[1..] {
            number = (number << 7) | u64::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((class, number))
}

pub(crate) fn encode_member<T: Encode + ?Sized>(
    member: &T,
    rules: EncodingType,
) -> Result<Vec<u8>, Asn1Error> {
    let mut encoding = vec![0; member.encoded_len(rules)];
    let written = member.encode(rules, &mut encoding)?;
    encoding.truncate(written);
    Ok(encoding)
}

pub(crate) fn copy_encodings<'a>(
    encodings: impl Iterator<Item = &'a [u8]>,
    out: &mut [u8],
) -> Result<usize, Asn1Error> {
    let mut at = 0;
    for encoding in encodings {
        let rest = out.get_mut(at..).ok_or(Asn1Error::BufferTooSmall)?;
        let target = rest
            .get_mut(..encoding.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        target.copy_from_slice(encoding);
        at += encoding.len();
    }
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Asn1Any, Asn1Boolean, Asn1Integer, Asn1Null, TryDecode};

    fn any(input: &[u8]) -> Asn1Any {
        Asn1Any::try_decode(input, Depth::DEFAULT).unwrap().1
    }

    #[test]
    fn a_set_of_orders_choice_encodings_with_81_before_a0_under_der() {
        let set = Asn1SetOf::from(vec![any(&[0xA0, 2, 0x30, 0]), any(&[0x81, 1, 5])]);
        assert_eq!(
            set.encode_to_vec(EncodingType::Der).unwrap(),
            [0x31, 7, 0x81, 1, 5, 0xA0, 2, 0x30, 0]
        );
        assert_eq!(
            set.encode_to_vec(EncodingType::Ber).unwrap(),
            [0x31, 7, 0xA0, 2, 0x30, 0, 0x81, 1, 5]
        );
    }

    #[test]
    fn a_set_of_places_false_before_true_without_changing_stored_members() {
        let mut set = Asn1SetOf::new();
        set.push(Asn1Boolean(true));
        set.push(Asn1Boolean(false));
        assert_eq!(
            set.encode_to_vec(EncodingType::Der).unwrap(),
            [0x31, 6, 1, 1, 0, 1, 1, 0xFF]
        );
        assert_eq!(set.members(), &[Asn1Boolean(true), Asn1Boolean(false)]);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_set_of_compares_length_octets_before_content_octets() {
        let set = Asn1SetOf::from(vec![any(&[4, 2, 0, 0]), any(&[4, 1, 0xFF])]);
        assert_eq!(
            set.encode_to_vec(EncodingType::Der).unwrap(),
            [0x31, 7, 4, 1, 0xFF, 4, 2, 0, 0]
        );
    }

    #[test]
    fn decoding_preserves_unsorted_input_and_ber_round_trips_it() {
        let input = [0x31, 6, 1, 1, 0xFF, 1, 1, 0];
        let (used, set) = Asn1SetOf::<Asn1Boolean>::try_decode(&input, Depth::DEFAULT).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(set.members(), &[Asn1Boolean(true), Asn1Boolean(false)]);
        assert_eq!(set.encode_to_vec(EncodingType::Ber).unwrap(), input);
        assert_ne!(set.encode_to_vec(EncodingType::Der).unwrap(), input);
    }

    #[test]
    fn a_sorted_set_of_round_trips_under_der() {
        let original: Asn1SetOf<Asn1Integer> =
            [1_u8, 2, 3].into_iter().map(Asn1Integer::from).collect();
        let bytes = original.encode_to_vec(EncodingType::Der).unwrap();
        let (_, decoded) = Asn1SetOf::<Asn1Integer>::try_decode(&bytes, Depth::DEFAULT).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn an_empty_set_of_encodes_as_a_header_alone() {
        let set_of = Asn1SetOf::<Asn1Null>::default();
        assert!(set_of.is_empty());
        for rules in [EncodingType::Ber, EncodingType::Der] {
            assert_eq!(set_of.encode_to_vec(rules).unwrap(), [0x31, 0]);
        }
        assert_eq!(
            Asn1SetOf::<Asn1Null>::try_decode(&[0x31, 0], Depth::DEFAULT),
            Ok((2, set_of))
        );
    }

    #[test]
    fn each_nested_set_of_consumes_one_level_of_depth() {
        let input = [0x31, 4, 0x31, 2, 0x31, 0];
        type Nested = Asn1SetOf<Asn1SetOf<Asn1SetOf<Asn1Null>>>;
        assert!(Nested::try_decode(&input, Depth::new(3)).is_ok());
        assert_eq!(
            Nested::try_decode(&input, Depth::new(2)).err(),
            Some(Asn1Error::DepthExceeded)
        );
    }

    #[test]
    fn a_wrong_outer_tag_or_member_type_rejects_the_whole_set_of() {
        assert_eq!(
            Asn1SetOf::<Asn1Boolean>::try_decode(&[0x30, 0], Depth::DEFAULT).err(),
            Some(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            Asn1SetOf::<Asn1Boolean>::try_decode(&[0x31, 2, 5, 0], Depth::DEFAULT).err(),
            Some(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn set_of_content_lengths_match_bytes_written() {
        let value = Asn1SetOf::from(vec![Asn1Boolean(true), Asn1Boolean(false)]);
        for rules in [EncodingType::Ber, EncodingType::Der] {
            let mut out = vec![0; value.content_len(rules)];
            assert_eq!(value.encode_content(rules, &mut out), Ok(out.len()));
            let mut too_small = vec![0; value.encoded_len(rules) - 1];
            assert_eq!(
                value.encode(rules, &mut too_small),
                Err(Asn1Error::BufferTooSmall)
            );
        }
    }
}
