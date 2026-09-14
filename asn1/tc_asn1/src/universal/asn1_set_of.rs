//! ASN.1 SET OF，採用 X.690 §11.6 的完整編碼排序。
//!
//! Bouncy Castle 的 `DerSet` 共用一套先比標籤、再遞迴比較子元素的規則。
//! 這裡以標準為準，不承諾 `SET OF` 與它產生相同位元組。例如 `SET OF CHOICE`
//! 的選項若有不同的 constructed 位，標籤號碼順序可能與完整編碼順序相反。
//! 一般 RDN 的直接成員都是 `SEQUENCE`，不會遇到這個直接成員標籤的反例。

#[cfg(test)]
use crate::Decode;
use alloc::vec;
use alloc::vec::Vec;

use crate::DecodingContext;
use crate::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

/// A homogeneous SET OF; insertion and decoding preserve order, while CER and DER sort output.
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
/// use tc_asn1::{Asn1Boolean, Asn1SetOf, Encode, EncodingOptions, EncodingType};
///
/// let values = Asn1SetOf::from(vec![Asn1Boolean::from(true), Asn1Boolean::from(false)]);
/// let mut out = [0; 8];
/// values.encode(&EncodingOptions::new(EncodingType::Der), &mut out).unwrap();
/// assert_eq!(out, [0x31, 6, 1, 1, 0, 1, 1, 0xFF]);
/// assert_eq!(values.members()[0], Asn1Boolean::from(true));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1SetOf<T> {
    members: Vec<T>,
}

impl<T> Asn1SetOf<T> {
    /// Universal identifier octets for this type's default encoding form.
    pub const TAG: &'static [u8] = super::tag::SET;

    /// Universal constructed identifier; identical to `TAG` because this type is always constructed.
    pub const CONSTRUCTED_TAG: &'static [u8] = Self::TAG;

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

impl<'a, T: crate::DecodeInner<'a>> crate::DecodeInner<'a> for Asn1SetOf<T> {
    fn decode_inner(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if !element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value = <Self as crate::DecodeContent<'a>>::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
    fn decode_inner_der(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if !element.is_constructed() {
            return Err(crate::Asn1Error::UnexpectedTag);
        }
        let value =
            <Self as crate::DecodeContent<'a>>::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}
impl<'a, T: crate::DecodeInner<'a>> crate::Decode<'a> for Asn1SetOf<T> {
    fn decode(
        buff: &'a [u8],
        options: &crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        <Self as crate::DecodeInner<'a>>::decode_inner(
            buff,
            &mut crate::DecodingContext::new(options),
        )
    }
}

impl<'a, T: crate::DecodeInner<'a>> DecodeContent<'a> for Asn1SetOf<T> {
    /// 逐一解碼並保留輸入順序，不排序也不驗序；任何成員失敗便整體失敗。
    /// 變動時間：分支只依編碼結構。
    fn decode_content(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        context.with_child(|context| {
            let mut children = crate::asn1_ref::ChildCursor::new(value, context.options());
            let mut members = Vec::new();
            while let Some(child) = children.next(context) {
                let child = child?;
                members.push(child.decode_as::<T>(context)?);
            }
            Ok(Self { members })
        })
    }

    fn decode_content_der(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        context.with_child(|context| {
            let mut children = crate::asn1_ref::ChildCursor::new(value, context.options());
            let mut members = Vec::new();
            let mut previous: Option<&[u8]> = None;
            while let Some(child) = children.next(context) {
                let child = child?;
                if previous.is_some_and(|raw| raw > child.raw()) {
                    return Err(Asn1Error::NotDer);
                }
                previous = Some(child.raw());
                members.push(child.decode_as_der::<T>(context)?);
            }
            Ok(Self { members })
        })
    }
}

impl<T: Encode> crate::EncodeContent for Asn1SetOf<T> {
    /// 加總成員的完整編碼長度，排序不影響長度。
    /// 變動時間：分支只依編碼結構。
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.members
            .iter()
            .map(|member| member.encoded_len(rules))
            .sum()
    }

    /// BER 的兩種長度形式都按原順序寫入；CER 與 DER 暫存成員編碼後依字典序寫入。
    /// 變動時間：依編碼結構分支，正規排序另比較成員的編碼位元組。
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        if !rules.is_canonical() {
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

impl<T: Encode> crate::EncodeTagged for Asn1SetOf<T> {}

impl<T: Encode> Encode for Asn1SetOf<T> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
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
    rules: &EncodingOptions,
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
    use crate::DecodingOptions;
    use crate::EncodeContent;
    use crate::EncodingType;
    use crate::{Asn1Any, Asn1Boolean, Asn1Integer, Asn1Null};

    fn any(input: &[u8]) -> Asn1Any {
        Asn1Any::decode(input, &DecodingOptions::default())
            .unwrap()
            .1
    }

    #[test]
    fn a_set_of_orders_choice_encodings_with_81_before_a0_under_der() {
        let set = Asn1SetOf::from(vec![any(&[0xA0, 2, 0x30, 0]), any(&[0x81, 1, 5])]);
        assert_eq!(
            set.encode_to_vec(&EncodingOptions::new(EncodingType::Der))
                .unwrap(),
            [0x31, 7, 0x81, 1, 5, 0xA0, 2, 0x30, 0]
        );
        assert_eq!(
            set.encode_to_vec(&EncodingOptions::new(EncodingType::Ber(
                crate::LengthForm::Definite
            )))
            .unwrap(),
            [0x31, 7, 0xA0, 2, 0x30, 0, 0x81, 1, 5]
        );
    }

    #[test]
    fn a_set_of_places_false_before_true_without_changing_stored_members() {
        let mut set = Asn1SetOf::new();
        set.push(Asn1Boolean::from(true));
        set.push(Asn1Boolean::from(false));
        assert_eq!(
            set.encode_to_vec(&EncodingOptions::new(EncodingType::Der))
                .unwrap(),
            [0x31, 6, 1, 1, 0, 1, 1, 0xFF]
        );
        assert_eq!(
            set.members(),
            &[Asn1Boolean::from(true), Asn1Boolean::from(false)]
        );
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_set_of_compares_length_octets_before_content_octets() {
        let set = Asn1SetOf::from(vec![any(&[4, 2, 0, 0]), any(&[4, 1, 0xFF])]);
        assert_eq!(
            set.encode_to_vec(&EncodingOptions::new(EncodingType::Der))
                .unwrap(),
            [0x31, 7, 4, 1, 0xFF, 4, 2, 0, 0]
        );
    }

    #[test]
    fn decoding_preserves_unsorted_input_and_ber_round_trips_it() {
        let input = [0x31, 6, 1, 1, 0xFF, 1, 1, 0];
        let (used, set) =
            Asn1SetOf::<Asn1Boolean>::decode(&input, &DecodingOptions::default()).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(
            set.members(),
            &[Asn1Boolean::from(true), Asn1Boolean::from(false)]
        );
        assert_eq!(
            set.encode_to_vec(&EncodingOptions::new(EncodingType::Ber(
                crate::LengthForm::Definite
            )))
            .unwrap(),
            input
        );
        assert_ne!(
            set.encode_to_vec(&EncodingOptions::new(EncodingType::Der))
                .unwrap(),
            input
        );
    }

    #[test]
    fn a_sorted_set_of_round_trips_under_der() {
        let original: Asn1SetOf<Asn1Integer> =
            [1_u8, 2, 3].into_iter().map(Asn1Integer::from).collect();
        let bytes = original
            .encode_to_vec(&EncodingOptions::new(EncodingType::Der))
            .unwrap();
        let (_, decoded) =
            Asn1SetOf::<Asn1Integer>::decode(&bytes, &DecodingOptions::default()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn an_empty_set_of_encodes_as_a_header_alone() {
        let set_of = Asn1SetOf::<Asn1Null>::default();
        assert!(set_of.is_empty());
        for rules in [
            &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Definite)),
            &EncodingOptions::new(EncodingType::Der),
        ] {
            assert_eq!(set_of.encode_to_vec(rules).unwrap(), [0x31, 0]);
        }
        assert_eq!(
            Asn1SetOf::<Asn1Null>::decode(&[0x31, 0], &DecodingOptions::default()),
            Ok((2, set_of))
        );
    }

    #[test]
    fn each_nested_set_of_consumes_one_level_of_depth() {
        let input = [0x31, 4, 0x31, 2, 0x31, 0];
        type Nested = Asn1SetOf<Asn1SetOf<Asn1SetOf<Asn1Null>>>;
        assert!(Nested::decode(&input, &DecodingOptions::new(3, 16 * 1024 * 1024, 65_536)).is_ok());
        assert_eq!(
            Nested::decode(&input, &DecodingOptions::new(2, 16 * 1024 * 1024, 65_536)).err(),
            Some(Asn1Error::DepthExceeded)
        );
    }

    #[test]
    fn the_schema_checks_the_outer_tag_and_members_validate_contents() {
        assert_eq!(
            crate::Fields::new(
                &[0x30, 0],
                &mut DecodingContext::new(&DecodingOptions::default())
            )
            .and_then(|mut fields| fields.required::<Asn1SetOf<Asn1Boolean>>(Asn1SetOf::<()>::TAG))
            .err(),
            Some(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            Asn1SetOf::<Asn1Boolean>::decode(&[0x31, 2, 5, 0], &DecodingOptions::default()).err(),
            Some(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn set_of_content_lengths_match_bytes_written() {
        let value = Asn1SetOf::from(vec![Asn1Boolean::from(true), Asn1Boolean::from(false)]);
        for rules in [
            &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Definite)),
            &EncodingOptions::new(EncodingType::Der),
        ] {
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
