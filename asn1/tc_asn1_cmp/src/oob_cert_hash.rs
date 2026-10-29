//! RFC 4210 §5.2.5 `OOBCertHash`, the hash of a root CA certificate sent out of
//! band.
//!
//! ```text
//! OOBCertHash ::= SEQUENCE {
//!     hashAlg [0] AlgorithmIdentifier OPTIONAL,
//!     certId  [1] CertId              OPTIONAL,
//!     hashVal BIT STRING }
//! ```
//!
//! The module uses explicit tags.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::crmf::CertId;

/// The hash of a certificate, its algorithm, and which certificate.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OobCertHash {
    hash_alg: Option<AlgorithmIdentifier>,
    cert_id: Option<CertId>,
    hash_val: Asn1BitString,
}

impl OobCertHash {
    /// The hash alone.
    /// Variable time: branches only on the encoding structure.
    pub fn new(hash_val: Asn1BitString) -> Self {
        Self {
            hash_alg: None,
            cert_id: None,
            hash_val,
        }
    }

    /// Sets the hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn with_hash_alg(mut self, hash_alg: AlgorithmIdentifier) -> Self {
        self.hash_alg = Some(hash_alg);
        self
    }

    /// Sets the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn with_cert_id(mut self, cert_id: CertId) -> Self {
        self.cert_id = Some(cert_id);
        self
    }

    /// Returns the hash algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_alg(&self) -> Option<&AlgorithmIdentifier> {
        self.hash_alg.as_ref()
    }

    /// Returns the certificate, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_id(&self) -> Option<&CertId> {
        self.cert_id.as_ref()
    }

    /// Returns the hash.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_val(&self) -> &Asn1BitString {
        &self.hash_val
    }
}

impl DecodeContent for OobCertHash {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let hash_alg = fields.get_explicit_opt::<AlgorithmIdentifier>([0xa0])?;
        let cert_id = fields.get_explicit_opt::<CertId>([0xa1])?;
        let hash_val = fields.get()?;
        fields.end()?;
        let value = Self {
            hash_alg,
            cert_id,
            hash_val,
        };
        Ok(value)
    }
}

impl DecodeInner for OobCertHash {
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

impl EncodeContent for OobCertHash {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.hash_alg
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .cert_id
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self.hash_val.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.hash_alg {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.cert_id {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self.hash_val.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OobCertHash {}

impl Tagged for OobCertHash {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OobCertHash {}

impl Encode for OobCertHash {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
