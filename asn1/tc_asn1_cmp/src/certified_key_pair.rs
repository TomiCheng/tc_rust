//! RFC 4210 §5.3.4 `CertifiedKeyPair`, an issued certificate and, optionally, its
//! private key.
//!
//! ```text
//! CertifiedKeyPair ::= SEQUENCE {
//!     certOrEncCert   CertOrEncCert,
//!     privateKey      [0] EncryptedKey       OPTIONAL,
//!     publicationInfo [1] PKIPublicationInfo OPTIONAL }
//! ```
//!
//! The module uses explicit tags.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::CertOrEncCert;
use crate::crmf::{EncryptedKey, PkiPublicationInfo};

/// The certificate, a private key the CA generated, and publication details.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertifiedKeyPair {
    cert_or_enc_cert: CertOrEncCert,
    private_key: Option<EncryptedKey>,
    publication_info: Option<PkiPublicationInfo>,
}

impl CertifiedKeyPair {
    /// The certificate alone.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_or_enc_cert: CertOrEncCert) -> Self {
        Self {
            cert_or_enc_cert,
            private_key: None,
            publication_info: None,
        }
    }

    /// Sets the encrypted private key.
    /// Variable time: branches only on the encoding structure.
    pub fn with_private_key(mut self, private_key: EncryptedKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the publication details.
    /// Variable time: branches only on the encoding structure.
    pub fn with_publication_info(mut self, publication_info: PkiPublicationInfo) -> Self {
        self.publication_info = Some(publication_info);
        self
    }

    /// Returns the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_or_enc_cert(&self) -> &CertOrEncCert {
        &self.cert_or_enc_cert
    }

    /// Returns the encrypted private key, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn private_key(&self) -> Option<&EncryptedKey> {
        self.private_key.as_ref()
    }

    /// Returns the publication details, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn publication_info(&self) -> Option<&PkiPublicationInfo> {
        self.publication_info.as_ref()
    }
}

impl DecodeContent for CertifiedKeyPair {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_or_enc_cert = fields.get()?;
        let private_key = fields.get_explicit_opt::<EncryptedKey>([0xa0])?;
        let publication_info = fields.get_explicit_opt::<PkiPublicationInfo>([0xa1])?;
        fields.end()?;
        let value = Self {
            cert_or_enc_cert,
            private_key,
            publication_info,
        };
        Ok(value)
    }
}

impl DecodeInner for CertifiedKeyPair {
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

impl EncodeContent for CertifiedKeyPair {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_or_enc_cert.encoded_len(rules)
            + self
                .private_key
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .publication_info
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_or_enc_cert.encode(rules, out)?;
        if let Some(v) = &self.private_key {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.publication_info {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertifiedKeyPair {}

impl Tagged for CertifiedKeyPair {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertifiedKeyPair {}

impl Encode for CertifiedKeyPair {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
