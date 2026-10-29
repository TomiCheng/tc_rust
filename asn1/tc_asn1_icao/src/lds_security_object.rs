//! ICAO Doc 9303 part 10 `LDSSecurityObject`, the document security object signed
//! by the issuing state.
//!
//! ```text
//! LDSSecurityObject ::= SEQUENCE {
//!     version             LDSSecurityObjectVersion,
//!     hashAlgorithm       DigestAlgorithmIdentifier,
//!     dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF DataGroupHash,
//!     ldsVersionInfo      LDSVersionInfo OPTIONAL } -- if present, version MUST be v1
//! LDSSecurityObjectVersion ::= INTEGER { v0(0), v1(1) }
//! ub-DataGroups INTEGER ::= 16
//! ```
//!
//! A version other than 1 alongside `ldsVersionInfo` is `MalformedValue`, as in
//! Bouncy Castle.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::{DataGroupHash, LdsVersionInfo};

/// The hash algorithm, the hash of each data group, and the LDS version.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LdsSecurityObject {
    version: Option<Asn1Integer>,
    hash_algorithm: AlgorithmIdentifier,
    data_group_hash_values: Asn1SequenceOf<DataGroupHash>,
    lds_version_info: Option<LdsVersionInfo>,
}

impl LdsSecurityObject {
    /// A version 0 object over 2 to 16 data groups; other counts are `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        hash_algorithm: AlgorithmIdentifier,
        data_group_hash_values: Vec<DataGroupHash>,
    ) -> Result<Self, Asn1Error> {
        Ok(Self {
            version: None,
            hash_algorithm,
            data_group_hash_values: data_groups(Asn1SequenceOf::new(data_group_hash_values))?,
            lds_version_info: None,
        })
    }

    /// Sets the LDS version, which makes the object version 1.
    /// Variable time: branches only on the encoding structure.
    pub fn with_lds_version_info(mut self, lds_version_info: LdsVersionInfo) -> Self {
        self.lds_version_info = Some(lds_version_info);
        self
    }

    /// Returns the decoded version, or the one Doc 9303 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// 1 with LDS version information, 0 otherwise.
    fn derived_version(&self) -> Asn1Integer {
        if self.lds_version_info.is_some() {
            1.into()
        } else {
            0.into()
        }
    }

    /// Returns the hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns the data group hashes in order.
    /// Variable time: branches only on the encoding structure.
    pub fn data_group_hash_values(&self) -> &[DataGroupHash] {
        self.data_group_hash_values.elements()
    }

    /// Returns the LDS version, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn lds_version_info(&self) -> Option<&LdsVersionInfo> {
        self.lds_version_info.as_ref()
    }
}

/// `MalformedValue` outside `SIZE (2..ub-DataGroups)`.
fn data_groups(
    hashes: Asn1SequenceOf<DataGroupHash>,
) -> Result<Asn1SequenceOf<DataGroupHash>, Asn1Error> {
    if (2..=16).contains(&hashes.elements().len()) {
        Ok(hashes)
    } else {
        Err(Asn1Error::MalformedValue)
    }
}

impl DecodeContent for LdsSecurityObject {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let hash_algorithm = fields.get()?;
        let data_group_hash_values = data_groups(fields.get()?)?;
        let lds_version_info = fields.get_opt()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            hash_algorithm,
            data_group_hash_values,
            lds_version_info,
        };
        if value.lds_version_info.is_some() && version != Asn1Integer::from(1) {
            return Err(Asn1Error::MalformedValue);
        }
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for LdsSecurityObject {
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

impl EncodeContent for LdsSecurityObject {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.hash_algorithm.encoded_len(rules)
            + self.data_group_hash_values.encoded_len(rules)
            + self
                .lds_version_info
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.hash_algorithm.encode(rules, &mut out[at..])?;
        at += self.data_group_hash_values.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.lds_version_info {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for LdsSecurityObject {}

impl Tagged for LdsSecurityObject {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for LdsSecurityObject {}

impl Encode for LdsSecurityObject {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
