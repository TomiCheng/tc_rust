//! RFC 5035 §4 `ESSCertIDv2`, a certificate by its hash under any algorithm.
//!
//! ```text
//! ESSCertIDv2 ::= SEQUENCE {
//!     hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
//!     certHash      Hash,
//!     issuerSerial  IssuerSerial OPTIONAL }
//! ```
//!
//! A written default `hashAlgorithm` is accepted under BER and rejected under
//! DER; encoding omits it. SHA-256 with NULL parameters is not the default.

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, NamedOid, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::attr::IssuerSerial;

/// The hash of a whole certificate, its algorithm, and optionally the issuer and
/// serial.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EssCertIdV2 {
    hash_algorithm: AlgorithmIdentifier,
    cert_hash: Asn1OctetString,
    issuer_serial: Option<IssuerSerial>,
}

impl EssCertIdV2 {
    /// The SHA-256 hash of the certificate, without the issuer and serial.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_hash: Asn1OctetString) -> Self {
        Self {
            hash_algorithm: default_hash_algorithm(),
            cert_hash,
            issuer_serial: None,
        }
    }

    /// Sets the hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn with_hash_algorithm(mut self, hash_algorithm: AlgorithmIdentifier) -> Self {
        self.hash_algorithm = hash_algorithm;
        self
    }

    /// Sets the issuer and serial.
    /// Variable time: branches only on the encoding structure.
    pub fn with_issuer_serial(mut self, issuer_serial: IssuerSerial) -> Self {
        self.issuer_serial = Some(issuer_serial);
        self
    }

    /// Returns the hash algorithm, SHA-256 when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns the hash of the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_hash(&self) -> &Asn1OctetString {
        &self.cert_hash
    }

    /// Returns the issuer and serial, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer_serial(&self) -> Option<&IssuerSerial> {
        self.issuer_serial.as_ref()
    }
}

const ID_SHA256: NamedOid = NamedOid::new(
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    "2.16.840.1.101.3.4.2.1",
    "id-sha256",
);

/// `{algorithm id-sha256}`, without parameters.
fn default_hash_algorithm() -> AlgorithmIdentifier {
    AlgorithmIdentifier::new(ID_SHA256.oid())
}

impl DecodeContent for EssCertIdV2 {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let hash_algorithm = fields.get_default(default_hash_algorithm())?;
        let cert_hash = fields.get()?;
        let issuer_serial = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            hash_algorithm,
            cert_hash,
            issuer_serial,
        };
        Ok(value)
    }
}

impl DecodeInner for EssCertIdV2 {
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

impl EncodeContent for EssCertIdV2 {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        (if self.hash_algorithm != default_hash_algorithm() {
            self.hash_algorithm.encoded_len(rules)
        } else {
            0
        }) + self.cert_hash.encoded_len(rules)
            + self
                .issuer_serial
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if self.hash_algorithm != default_hash_algorithm() {
            at += self.hash_algorithm.encode(rules, &mut out[at..])?;
        }
        at += self.cert_hash.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.issuer_serial {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for EssCertIdV2 {}

impl Tagged for EssCertIdV2 {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EssCertIdV2 {}

impl Encode for EssCertIdV2 {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
