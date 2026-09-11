//! ASN.1 `SET OF` 與 `SET`，分別採用 X.690 §11.6 與 §10.3 的排序。
//!
//! Bouncy Castle 的 `DerSet` 共用一套先比標籤、再遞迴比較子元素的規則。
//! 這裡以標準為準，不承諾 `SET OF` 與它產生相同位元組。例如 `SET OF CHOICE`
//! 的選項若有不同的 constructed 位，標籤號碼順序可能與完整編碼順序相反。
//! 一般 RDN 的直接成員都是 `SEQUENCE`，不會遇到這個直接成員標籤的反例。

use alloc::boxed::Box;
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

/// 異質 `SET` 的編碼側建構器；依 X.690 §10.3 的標籤類別、號碼排序。
///
/// 與 [`Asn1SetOf`] 是獨立型別，不解碼。呼叫端的結構定義必須確保成員標籤相異；
/// 此建構器不驗證結構定義，重複標籤在 DER 輸出時仍保留相對加入順序。
/// 標籤號碼支援至 `u64::MAX`，超過時 DER 編碼回傳 [`Asn1Error::TagOverflow`]。
///
/// 成員必須自行產生 DER，
/// 此建構器只決定順序，不正規化 [`crate::Asn1Any`] 保存的原始編碼。
///
/// # Examples
///
/// 不同型別的欄位按標籤排序，BOOLEAN 在 NULL 前面。
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Null, Asn1Set, Encode, EncodingType};
///
/// let mut value = Asn1Set::new();
/// value.push_boxed(Asn1Null);
/// value.push_boxed(Asn1Boolean(true));
/// let mut out = [0; 7];
/// value.encode(EncodingType::Der, &mut out).unwrap();
/// assert_eq!(out, [0x31, 5, 1, 1, 0xFF, 5, 0]);
/// ```
pub struct Asn1Set {
    members: Vec<Box<dyn Encode>>,
}

impl Asn1Set {
    /// 建立空集合。
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// 在尾端加入已裝箱的成員。
    pub fn push(&mut self, member: Box<dyn Encode>) {
        self.members.push(member);
    }

    /// 裝箱並加入可編碼的成員。
    pub fn push_boxed<E: Encode + 'static>(&mut self, member: E) {
        self.push(Box::new(member));
    }

    /// 借用原順序的成員。
    pub fn members(&self) -> &[Box<dyn Encode>] {
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

impl Default for Asn1Set {
    /// 建立空集合。
    fn default() -> Self {
        Self::new()
    }
}

impl Encode for Asn1Set {
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

    /// BER 按原順序寫入；DER 按標籤類別、號碼穩定排序，不比較 constructed 位。
    /// 變動時間：依編碼結構分支，DER 排序比較標籤的類別與號碼。
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
            .map(|member| {
                let tag = member.tag();
                // 解析器保留任意長度的標籤；轉成排序鍵之前另檢查 u64 上限。
                if tag.len() > 11 || (tag.len() == 11 && tag[1] & 0x7F > 1) {
                    return Err(Asn1Error::TagOverflow);
                }
                if tag.is_empty() {
                    return Err(Asn1Error::MalformedValue);
                }
                Ok((tag_key(tag), encode_member(member, rules)?))
            })
            .collect::<Result<Vec<_>, _>>()?;
        encodings.sort_by_key(|(key, _)| *key);
        copy_encodings(
            encodings.iter().map(|(_, encoding)| encoding.as_slice()),
            out,
        )
    }
}

// 呼叫端已確認標籤非空且號碼可放入 u64；標籤須為合法的識別位元組。
fn tag_key(tag: &[u8]) -> (u8, u64) {
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
    (class, number)
}

fn encode_member<T: Encode + ?Sized>(
    member: &T,
    rules: EncodingType,
) -> Result<Vec<u8>, Asn1Error> {
    let mut encoding = vec![0; member.encoded_len(rules)];
    let written = member.encode(rules, &mut encoding)?;
    encoding.truncate(written);
    Ok(encoding)
}

fn copy_encodings<'a>(
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

    fn encoded(value: &impl Encode, rules: EncodingType) -> Vec<u8> {
        encode_member(value, rules).unwrap()
    }

    #[test]
    fn der_places_boolean_before_null_while_ber_preserves_insertion_order() {
        let mut set = Asn1Set::new();
        set.push_boxed(Asn1Null);
        set.push_boxed(Asn1Boolean(true));
        assert_eq!(
            encoded(&set, EncodingType::Der),
            [0x31, 5, 1, 1, 0xFF, 5, 0]
        );
        assert_eq!(
            encoded(&set, EncodingType::Ber),
            [0x31, 5, 5, 0, 1, 1, 0xFF]
        );
        assert_eq!(set.members()[0].tag(), &[5]);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_set_of_orders_choice_encodings_with_81_before_a0_under_der() {
        let set = Asn1SetOf::from(vec![any(&[0xA0, 2, 0x30, 0]), any(&[0x81, 1, 5])]);
        assert_eq!(
            encoded(&set, EncodingType::Der),
            [0x31, 7, 0x81, 1, 5, 0xA0, 2, 0x30, 0]
        );
        assert_eq!(
            encoded(&set, EncodingType::Ber),
            [0x31, 7, 0xA0, 2, 0x30, 0, 0x81, 1, 5]
        );
    }

    #[test]
    fn a_set_orders_choice_tags_with_a0_before_81_under_der() {
        let mut set = Asn1Set::new();
        set.push_boxed(any(&[0x81, 1, 5]));
        set.push_boxed(any(&[0xA0, 2, 0x30, 0]));
        assert_eq!(
            encoded(&set, EncodingType::Der),
            [0x31, 7, 0xA0, 2, 0x30, 0, 0x81, 1, 5]
        );
        assert_eq!(
            encoded(&set, EncodingType::Ber),
            [0x31, 7, 0x81, 1, 5, 0xA0, 2, 0x30, 0]
        );
    }

    #[test]
    fn a_set_of_places_false_before_true_without_changing_stored_members() {
        let mut set = Asn1SetOf::new();
        set.push(Asn1Boolean(true));
        set.push(Asn1Boolean(false));
        assert_eq!(
            encoded(&set, EncodingType::Der),
            [0x31, 6, 1, 1, 0, 1, 1, 0xFF]
        );
        assert_eq!(set.members(), &[Asn1Boolean(true), Asn1Boolean(false)]);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_set_preserves_insertion_order_for_equal_tag_keys() {
        let mut set = Asn1Set::new();
        set.push_boxed(Asn1Boolean(true));
        set.push_boxed(Asn1Boolean(false));
        assert_eq!(
            encoded(&set, EncodingType::Der),
            [0x31, 6, 1, 1, 0xFF, 1, 1, 0]
        );
    }

    #[test]
    fn a_set_sorts_high_tag_numbers_numerically_after_their_class() {
        let mut set = Asn1Set::new();
        for input in [
            &[0xC0, 0][..],
            &[0x9F, 0x81, 0x80, 0, 0],
            &[0x9F, 0xFF, 0x7F, 0],
            &[0x5F, 0x82, 0, 0],
        ] {
            set.push_boxed(any(input));
        }
        assert_eq!(
            encoded(&set, EncodingType::Der),
            [
                0x31, 15, 0x5F, 0x82, 0, 0, 0x9F, 0xFF, 0x7F, 0, 0x9F, 0x81, 0x80, 0, 0, 0xC0, 0
            ]
        );
    }

    #[test]
    fn a_set_rejects_tag_numbers_above_u64_without_wrapping_the_sort_key() {
        let mut max = vec![0x9F, 0x81];
        max.extend_from_slice(&[0xFF; 8]);
        max.extend_from_slice(&[0x7F, 0]);
        let mut set = Asn1Set::new();
        set.push_boxed(any(&max));
        assert!(set.encode(EncodingType::Der, &mut [0; 32]).is_ok());
        assert_eq!(tag_key(&max[..11]), (2, u64::MAX));
        max[1] = 0x82;
        set.push_boxed(any(&max));
        assert_eq!(
            set.encode(EncodingType::Der, &mut [0; 32]),
            Err(Asn1Error::TagOverflow)
        );
    }

    #[test]
    fn a_set_of_compares_length_octets_before_content_octets() {
        let set = Asn1SetOf::from(vec![any(&[4, 2, 0, 0]), any(&[4, 1, 0xFF])]);
        assert_eq!(
            encoded(&set, EncodingType::Der),
            [0x31, 7, 4, 1, 0xFF, 4, 2, 0, 0]
        );
    }

    #[test]
    fn decoding_preserves_unsorted_input_and_ber_round_trips_it() {
        let input = [0x31, 6, 1, 1, 0xFF, 1, 1, 0];
        let (used, set) = Asn1SetOf::<Asn1Boolean>::try_decode(&input, Depth::DEFAULT).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(set.members(), &[Asn1Boolean(true), Asn1Boolean(false)]);
        assert_eq!(encoded(&set, EncodingType::Ber), input);
        assert_ne!(encoded(&set, EncodingType::Der), input);
    }

    #[test]
    fn a_sorted_set_of_round_trips_under_der() {
        let original: Asn1SetOf<Asn1Integer> =
            [1_u8, 2, 3].into_iter().map(Asn1Integer::from).collect();
        let bytes = encoded(&original, EncodingType::Der);
        let (_, decoded) = Asn1SetOf::<Asn1Integer>::try_decode(&bytes, Depth::DEFAULT).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn both_empty_sets_encode_as_a_header_alone() {
        let set = Asn1Set::default();
        let set_of = Asn1SetOf::<Asn1Null>::default();
        assert!(set.is_empty());
        assert!(set_of.is_empty());
        for rules in [EncodingType::Ber, EncodingType::Der] {
            assert_eq!(encoded(&set, rules), [0x31, 0]);
            assert_eq!(encoded(&set_of, rules), [0x31, 0]);
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
    fn content_lengths_match_bytes_written_for_both_set_types() {
        let set_of = Asn1SetOf::from(vec![Asn1Boolean(true), Asn1Boolean(false)]);
        let mut set = Asn1Set::new();
        set.push_boxed(Asn1Null);
        set.push_boxed(Asn1Boolean(true));
        for value in [&set_of as &dyn Encode, &set as &dyn Encode] {
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
}
