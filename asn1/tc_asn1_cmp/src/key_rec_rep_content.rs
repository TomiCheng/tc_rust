//! RFC 4210 §5.3.8 `KeyRecRepContent`, the body of a key recovery response.
//!
//! ```text
//! KeyRecRepContent ::= SEQUENCE {
//!     status      PKIStatusInfo,
//!     newSigCert  [0] CMPCertificate OPTIONAL,
//!     caCerts     [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
//!     keyPairHist [2] SEQUENCE SIZE (1..MAX) OF CertifiedKeyPair OPTIONAL }
//! ```
//!
//! The module uses explicit tags.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::{CertifiedKeyPair, CmpCertificate, PkiStatusInfo};

/// The status, a new signing certificate, CA certificates and recovered keys.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KeyRecRepContent {
    status: PkiStatusInfo,
    new_sig_cert: Option<CmpCertificate>,
    ca_certs: Option<Asn1SequenceOf<CmpCertificate>>,
    key_pair_hist: Option<Asn1SequenceOf<CertifiedKeyPair>>,
}

impl KeyRecRepContent {
    /// A status alone.
    /// Variable time: branches only on the encoding structure.
    pub fn new(status: PkiStatusInfo) -> Self {
        Self {
            status,
            new_sig_cert: None,
            ca_certs: None,
            key_pair_hist: None,
        }
    }

    /// Sets the new signing certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn with_new_sig_cert(mut self, new_sig_cert: CmpCertificate) -> Self {
        self.new_sig_cert = Some(new_sig_cert);
        self
    }

    /// Sets the CA certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ca_certs(mut self, ca_certs: Vec<CmpCertificate>) -> Self {
        self.ca_certs = Some(Asn1SequenceOf::new(ca_certs));
        self
    }

    /// Sets the recovered key pairs.
    /// Variable time: branches only on the encoding structure.
    pub fn with_key_pair_hist(mut self, key_pair_hist: Vec<CertifiedKeyPair>) -> Self {
        self.key_pair_hist = Some(Asn1SequenceOf::new(key_pair_hist));
        self
    }

    /// Returns the status.
    /// Variable time: branches only on the encoding structure.
    pub fn status(&self) -> &PkiStatusInfo {
        &self.status
    }

    /// Returns the new signing certificate, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn new_sig_cert(&self) -> Option<&CmpCertificate> {
        self.new_sig_cert.as_ref()
    }

    /// Returns the CA certificates, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn ca_certs(&self) -> Option<&[CmpCertificate]> {
        self.ca_certs.as_ref().map(Asn1SequenceOf::elements)
    }

    /// Returns the recovered key pairs, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn key_pair_hist(&self) -> Option<&[CertifiedKeyPair]> {
        self.key_pair_hist.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for KeyRecRepContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let status = fields.get()?;
        let new_sig_cert = fields.get_explicit_opt::<CmpCertificate>([0xa0])?;
        let ca_certs = fields.get_explicit_opt::<Asn1SequenceOf<CmpCertificate>>([0xa1])?;
        let key_pair_hist = fields.get_explicit_opt::<Asn1SequenceOf<CertifiedKeyPair>>([0xa2])?;
        fields.end()?;
        let value = Self {
            status,
            new_sig_cert,
            ca_certs,
            key_pair_hist,
        };
        Ok(value)
    }
}

impl DecodeInner for KeyRecRepContent {
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

impl EncodeContent for KeyRecRepContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.status.encoded_len(rules)
            + self
                .new_sig_cert
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .ca_certs
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .key_pair_hist
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.status.encode(rules, out)?;
        if let Some(v) = &self.new_sig_cert {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.ca_certs {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.key_pair_hist {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for KeyRecRepContent {}

impl Tagged for KeyRecRepContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KeyRecRepContent {}

impl Encode for KeyRecRepContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
