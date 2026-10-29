//! RFC 6960 §4.1.1 `CertID`, which names a certificate by hashes of its
//! issuer and its serial number.
//!
//! ```text
//! CertID ::= SEQUENCE {
//!     hashAlgorithm  AlgorithmIdentifier,
//!     issuerNameHash OCTET STRING, -- Hash of issuer's DN
//!     issuerKeyHash  OCTET STRING, -- Hash of issuer's public key
//!     serialNumber   CertificateSerialNumber }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// A certificate as its issuer's name and key hashes and its serial number.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertId {
    hash_algorithm: AlgorithmIdentifier,
    issuer_name_hash: Asn1OctetString,
    issuer_key_hash: Asn1OctetString,
    serial_number: Asn1Integer,
}

impl CertId {
    /// The hash algorithm, both issuer hashes and the serial number.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        hash_algorithm: AlgorithmIdentifier,
        issuer_name_hash: Asn1OctetString,
        issuer_key_hash: Asn1OctetString,
        serial_number: Asn1Integer,
    ) -> Self {
        Self {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        }
    }

    /// Returns the algorithm of both hashes.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns the hash of the issuer's DER-encoded name.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer_name_hash(&self) -> &Asn1OctetString {
        &self.issuer_name_hash
    }

    /// Returns the hash of the issuer's public key bits.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer_key_hash(&self) -> &Asn1OctetString {
        &self.issuer_key_hash
    }

    /// Returns the certificate's serial number.
    /// Variable time: branches only on the encoding structure.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }
}

impl DecodeContent for CertId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let hash_algorithm = fields.get()?;
        let issuer_name_hash = fields.get()?;
        let issuer_key_hash = fields.get()?;
        let serial_number = fields.get()?;
        fields.end()?;
        let value = Self {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        };
        Ok(value)
    }
}

impl DecodeInner for CertId {
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

impl EncodeContent for CertId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.hash_algorithm.encoded_len(rules)
            + self.issuer_name_hash.encoded_len(rules)
            + self.issuer_key_hash.encoded_len(rules)
            + self.serial_number.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.hash_algorithm.encode(rules, out)?;
        at += self.issuer_name_hash.encode(rules, &mut out[at..])?;
        at += self.issuer_key_hash.encode(rules, &mut out[at..])?;
        at += self.serial_number.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CertId {}

impl Tagged for CertId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertId {}

impl Encode for CertId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
