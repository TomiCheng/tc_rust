//! ASN.1 `SEQUENCE OF`。

use alloc::vec::Vec;

use crate::asn1_ref::Children;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

use super::tag::SEQUENCE as TAG;

/// 有序、同型別。三種規則下順序都不動，所以是最簡單的集合。
///
/// 異質結構可使用 [`crate::Asn1Object::Sequence`]。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1SequenceOf<T> {
    members: Vec<T>,
}

impl<T> Asn1SequenceOf<T> {
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    pub fn push(&mut self, member: T) {
        self.members.push(member);
    }

    pub fn members(&self) -> &[T] {
        &self.members
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

impl<T> Default for Asn1SequenceOf<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<T>> for Asn1SequenceOf<T> {
    fn from(members: Vec<T>) -> Self {
        Self { members }
    }
}

impl<T> FromIterator<T> for Asn1SequenceOf<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            members: iter.into_iter().collect(),
        }
    }
}

impl<'a, T: DecodeContent<'a>> DecodeContent<'a> for Asn1SequenceOf<T> {
    const TAG: &'static [u8] = TAG;

    /// 急切解：每個子元素當場 `decode_as::<T>`，任何一個失敗整個失敗。
    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        let members = Children::new(value, depth)
            .map(|child| child?.decode_as::<T>(depth))
            .collect::<Result<Vec<T>, _>>()?;
        Ok(Self { members })
    }
}

impl<T: Encode> Encode for Asn1SequenceOf<T> {
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, rules: EncodingType) -> usize {
        self.members.iter().map(|m| m.encoded_len(rules)).sum()
    }
    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        for member in &self.members {
            at += member.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Decode;
    use crate::universal::{Asn1Boolean, Asn1Integer, Asn1Null};

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn a_homogeneous_sequence_decodes_each_member_as_t() {
        // 30 06  01 01 FF  01 01 00
        let input = [0x30, 0x06, 0x01, 0x01, 0xFF, 0x01, 0x01, 0x00];
        let (used, seq) = Asn1SequenceOf::<Asn1Boolean>::try_decode(&input, DEPTH).unwrap();

        assert_eq!(used, 8);
        assert_eq!(seq.members(), &[Asn1Boolean(true), Asn1Boolean(false)]);
    }

    #[test]
    fn a_member_of_the_wrong_type_fails_the_whole_sequence() {
        let input = [0x30, 0x05, 0x01, 0x01, 0xFF, 0x05, 0x00];
        assert_eq!(
            Asn1SequenceOf::<Asn1Boolean>::try_decode(&input, DEPTH).err(),
            Some(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn order_is_preserved_under_every_rule() {
        let mut seq = Asn1SequenceOf::new();
        seq.push(Asn1Integer::from(2_u8));
        seq.push(Asn1Integer::from(1_u8));

        for rules in [EncodingType::Ber, EncodingType::Der] {
            let mut out = [0_u8; 16];
            let written = seq.encode(rules, &mut out).unwrap();
            assert_eq!(
                &out[..written],
                &[0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01],
                "{rules:?}"
            );
            assert_eq!(written, seq.encoded_len(rules));
        }
    }

    #[test]
    fn an_empty_sequence_is_a_header_alone() {
        let (used, seq) = Asn1SequenceOf::<Asn1Null>::try_decode(&[0x30, 0x00], DEPTH).unwrap();
        assert_eq!(used, 2);
        assert!(seq.is_empty());

        let mut out = [0_u8; 4];
        assert_eq!(seq.encode(EncodingType::Der, &mut out).unwrap(), 2);
        assert_eq!(&out[..2], &[0x30, 0x00]);
    }

    #[test]
    fn nesting_spends_depth() {
        // 30 04  30 02  30 00 —— 三層
        let input = [0x30, 0x04, 0x30, 0x02, 0x30, 0x00];
        type Nested = Asn1SequenceOf<Asn1SequenceOf<Asn1SequenceOf<Asn1Null>>>;
        assert!(Nested::try_decode(&input, Depth::new(3)).is_ok());
        assert_eq!(
            Nested::try_decode(&input, Depth::new(2)).err(),
            Some(Asn1Error::DepthExceeded)
        );
    }

    #[test]
    fn a_sequence_round_trips() {
        let original: Asn1SequenceOf<Asn1Integer> =
            [1_u8, 2, 3].into_iter().map(Asn1Integer::from).collect();
        let mut out = [0_u8; 16];
        let written = original.encode(EncodingType::Der, &mut out).unwrap();
        let (_, decoded) =
            Asn1SequenceOf::<Asn1Integer>::try_decode(&out[..written], DEPTH).unwrap();
        assert_eq!(decoded, original);
    }
}
