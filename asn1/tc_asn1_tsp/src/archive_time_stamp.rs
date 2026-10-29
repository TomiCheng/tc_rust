//! RFC 4998 §4.2 `ArchiveTimeStamp`, a time-stamp over the root of a hash tree.
//!
//! ```text
//! ArchiveTimeStamp ::= SEQUENCE {
//!     digestAlgorithm [0] AlgorithmIdentifier          OPTIONAL,
//!     attributes      [1] Attributes                   OPTIONAL,
//!     reducedHashtree [2] SEQUENCE OF PartialHashtree  OPTIONAL,
//!     timeStamp       ContentInfo }
//! Attributes ::= SET SIZE (1..MAX) OF Attribute
//! ```
//!
//! The module uses implicit tags.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_cms::content::ContentInfo;
use tc_asn1_x500::Attribute;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::PartialHashtree;

/// A time-stamp, the reduced hash tree that leads to what it signs, and the
/// algorithm of that tree.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArchiveTimeStamp {
    digest_algorithm: Option<AlgorithmIdentifier>,
    attributes: Option<Asn1SetOf<Attribute>>,
    reduced_hashtree: Option<Asn1SequenceOf<PartialHashtree>>,
    time_stamp: ContentInfo,
}

impl ArchiveTimeStamp {
    /// The time-stamp alone, for a single data object.
    /// Variable time: branches only on the encoding structure.
    pub fn new(time_stamp: ContentInfo) -> Self {
        Self {
            digest_algorithm: None,
            attributes: None,
            reduced_hashtree: None,
            time_stamp,
        }
    }

    /// Sets the hash algorithm of the tree, when the time-stamp does not say it.
    /// Variable time: branches only on the encoding structure.
    pub fn with_digest_algorithm(mut self, digest_algorithm: AlgorithmIdentifier) -> Self {
        self.digest_algorithm = Some(digest_algorithm);
        self
    }

    /// Sets the attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn with_attributes(mut self, attributes: Vec<Attribute>) -> Self {
        self.attributes = Some(Asn1SetOf::new(attributes));
        self
    }

    /// Sets the reduced hash tree, leaf level first.
    /// Variable time: branches only on the encoding structure.
    pub fn with_reduced_hashtree(mut self, reduced_hashtree: Vec<PartialHashtree>) -> Self {
        self.reduced_hashtree = Some(Asn1SequenceOf::new(reduced_hashtree));
        self
    }

    /// Returns the hash algorithm of the tree, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithm(&self) -> Option<&AlgorithmIdentifier> {
        self.digest_algorithm.as_ref()
    }

    /// Returns the attributes, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn attributes(&self) -> Option<&[Attribute]> {
        self.attributes.as_ref().map(Asn1SetOf::members)
    }

    /// Returns the reduced hash tree, leaf level first, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn reduced_hashtree(&self) -> Option<&[PartialHashtree]> {
        self.reduced_hashtree.as_ref().map(Asn1SequenceOf::elements)
    }

    /// Returns the time-stamp token.
    /// Variable time: branches only on the encoding structure.
    pub fn time_stamp(&self) -> &ContentInfo {
        &self.time_stamp
    }
}

impl DecodeContent for ArchiveTimeStamp {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let digest_algorithm = fields.get_implicit_opt([0xa0])?;
        let attributes = fields.get_implicit_opt([0xa1])?;
        let reduced_hashtree = fields.get_implicit_opt([0xa2])?;
        let time_stamp = fields.get()?;
        fields.end()?;
        let value = Self {
            digest_algorithm,
            attributes,
            reduced_hashtree,
            time_stamp,
        };
        Ok(value)
    }
}

impl DecodeInner for ArchiveTimeStamp {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for ArchiveTimeStamp {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.digest_algorithm
            .as_ref()
            .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .attributes
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .reduced_hashtree
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa2], v).encoded_len(rules))
            + self.time_stamp.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.digest_algorithm {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.attributes {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.reduced_hashtree {
            at += Implicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        at += self.time_stamp.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ArchiveTimeStamp {}

impl Tagged for ArchiveTimeStamp {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ArchiveTimeStamp {}

impl Encode for ArchiveTimeStamp {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
