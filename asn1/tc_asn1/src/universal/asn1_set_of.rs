//! SET OF: an [`Asn1Constructed`] under tag 31 whose CER and DER output is sorted.

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

use super::cer_common::constructed_tag;
use crate::traits::encode::{default_encode, default_encoded_len};
use crate::{
    Asn1Constructed, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, EncodingType, Tagged,
};

const DER: EncodingOptions = EncodingOptions::new(EncodingType::Der);

/// A homogeneous SET OF. Construction and decoding keep the given order; CER
/// and DER write the members sorted by their encodings (X.690 §11.6), BER
/// writes them as stored.
#[derive(Clone, Debug)]
pub struct Asn1SetOf<T> {
    members: Asn1Constructed<T>,
}

/// Two sets are equal when their DER encodings are, so the stored order does
/// not matter. Should encoding fail, which a valid value never does under DER,
/// the sets compare unequal, even to themselves.
impl<T: Encode> PartialEq for Asn1SetOf<T> {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self.encode_to_vec(&DER), other.encode_to_vec(&DER)),
            (Ok(a), Ok(b)) if a == b
        )
    }
}

impl<T: Encode> Eq for Asn1SetOf<T> {}

/// Hashes the DER encoding, matching [`PartialEq`].
impl<T: Encode> Hash for Asn1SetOf<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Ok(der) = self.encode_to_vec(&DER) {
            der.hash(state);
        }
    }
}

impl<T> Asn1SetOf<T> {
    pub const TAG: &'static [u8] = super::tag::SET;

    pub fn new(members: Vec<T>) -> Self {
        Self {
            members: Asn1Constructed::new(Self::TAG, members),
        }
    }

    pub fn members(&self) -> &[T] {
        self.members.items()
    }

    pub fn into_members(self) -> Vec<T> {
        self.members.into_items()
    }
}

impl<T: DecodeInner> DecodeInner for Asn1SetOf<T> {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, members) = Asn1Constructed::decode_inner(buff, context)?;
        if members.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        Ok((used, Self { members }))
    }
}

impl<T: DecodeInner> Decode for Asn1SetOf<T> {}
impl<T> Tagged for Asn1SetOf<T> {
    const TAG: &'static [u8] = Self::TAG;
}

impl<T: Encode> EncodeContent for Asn1SetOf<T> {
    /// Sorting does not change the length. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.members.content_len(rules)
    }

    /// BER writes the members as stored. CER and DER encode each member,
    /// sort the encodings as octet strings and write them in that order.
    /// Variable time: the sort compares public encodings.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        if !rules.is_canonical() {
            return self.members.encode_content(rules, out);
        }
        let mut encodings = self
            .members
            .items()
            .iter()
            .map(|member| member.encode_to_vec(rules))
            .collect::<Result<Vec<_>, _>>()?;
        encodings.sort();
        let total = encodings.iter().map(Vec::len).sum();
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        let mut at = 0;
        for encoding in &encodings {
            out[at..at + encoding.len()].copy_from_slice(encoding);
            at += encoding.len();
        }
        Ok(at)
    }
}

/// The default header with the constructed bit forced on, as for [`Asn1Constructed`].
impl<T: Encode> EncodeTagged for Asn1SetOf<T> {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        default_encoded_len(self, &constructed_tag(tag), rules)
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        default_encode(self, &constructed_tag(tag), rules, out)
    }
}

impl<T: Encode> Encode for Asn1SetOf<T> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
