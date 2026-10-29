//! RFC 4998 §3 `EvidenceRecord`, proof that data existed and stayed intact
//! across renewed time-stamps.
//!
//! ```text
//! EvidenceRecord ::= SEQUENCE {
//!     version                  INTEGER { v1(1) },
//!     digestAlgorithms         SEQUENCE OF AlgorithmIdentifier,
//!     cryptoInfos              [0] CryptoInfos    OPTIONAL,
//!     encryptionInfo           [1] EncryptionInfo OPTIONAL,
//!     archiveTimeStampSequence ArchiveTimeStampSequence }
//! ```
//!
//! The module uses implicit tags. Versions other than 1 are rejected.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::{ArchiveTimeStampSequence, CryptoInfos, EncryptionInfo};

/// The hash algorithms used, verification data, and the archive time-stamps.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EvidenceRecord {
    version: Option<Asn1Integer>,
    digest_algorithms: Asn1SequenceOf<AlgorithmIdentifier>,
    crypto_infos: Option<CryptoInfos>,
    encryption_info: Option<EncryptionInfo>,
    archive_time_stamp_sequence: ArchiveTimeStampSequence,
}

impl EvidenceRecord {
    /// A version 1 record without verification or encryption information.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        digest_algorithms: Vec<AlgorithmIdentifier>,
        archive_time_stamp_sequence: ArchiveTimeStampSequence,
    ) -> Self {
        Self {
            version: None,
            digest_algorithms: Asn1SequenceOf::new(digest_algorithms),
            crypto_infos: None,
            encryption_info: None,
            archive_time_stamp_sequence,
        }
    }

    /// Sets the verification data.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crypto_infos(mut self, crypto_infos: CryptoInfos) -> Self {
        self.crypto_infos = Some(crypto_infos);
        self
    }

    /// Sets how the data was encrypted.
    /// Variable time: branches only on the encoding structure.
    pub fn with_encryption_info(mut self, encryption_info: EncryptionInfo) -> Self {
        self.encryption_info = Some(encryption_info);
        self
    }

    /// Returns the decoded version, or the one RFC 4998 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 1.
    fn derived_version(&self) -> Asn1Integer {
        1.into()
    }

    /// Returns the hash algorithms used, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier] {
        self.digest_algorithms.elements()
    }

    /// Returns the verification data, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crypto_infos(&self) -> Option<&CryptoInfos> {
        self.crypto_infos.as_ref()
    }

    /// Returns how the data was encrypted, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_info(&self) -> Option<&EncryptionInfo> {
        self.encryption_info.as_ref()
    }

    /// Returns the archive time-stamps.
    /// Variable time: branches only on the encoding structure.
    pub fn archive_time_stamp_sequence(&self) -> &ArchiveTimeStampSequence {
        &self.archive_time_stamp_sequence
    }
}

impl DecodeContent for EvidenceRecord {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let digest_algorithms = fields.get()?;
        let crypto_infos = fields.get_implicit_opt([0xa0])?;
        let encryption_info = fields.get_implicit_opt([0xa1])?;
        let archive_time_stamp_sequence = fields.get()?;
        fields.end()?;
        if version != Asn1Integer::from(1) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            version: None,
            digest_algorithms,
            crypto_infos,
            encryption_info,
            archive_time_stamp_sequence,
        })
    }
}

impl DecodeInner for EvidenceRecord {
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

impl EncodeContent for EvidenceRecord {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.digest_algorithms.encoded_len(rules)
            + self
                .crypto_infos
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .encryption_info
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
            + self.archive_time_stamp_sequence.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.digest_algorithms.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.crypto_infos {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.encryption_info {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self
            .archive_time_stamp_sequence
            .encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for EvidenceRecord {}

impl Tagged for EvidenceRecord {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EvidenceRecord {}

impl Encode for EvidenceRecord {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
