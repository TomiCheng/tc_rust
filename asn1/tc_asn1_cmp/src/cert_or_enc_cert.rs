//! RFC 4210 §5.3.4 `CertOrEncCert`, an issued certificate, plain or encrypted.
//!
//! ```text
//! CertOrEncCert ::= CHOICE {
//!     certificate   [0] CMPCertificate,
//!     encryptedCert [1] EncryptedKey }
//! ```
//!
//! The module uses explicit tags.

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit,
};

use crate::CmpCertificate;
use crate::crmf::EncryptedKey;

/// The certificate, or the certificate encrypted for the requester.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep every alternative inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum CertOrEncCert {
    /// `[0]`, the certificate.
    Certificate(CmpCertificate),
    /// `[1]`, the certificate encrypted, to prove possession of a decryption key.
    EncryptedCert(EncryptedKey),
}

impl DecodeInner for CertOrEncCert {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0xa0] => {
                let mut inner = element.children(context)?;
                let value = Self::Certificate(inner.get()?);
                inner.end()?;
                value
            }
            [0xa1] => {
                let mut inner = element.children(context)?;
                let value = Self::EncryptedCert(inner.get()?);
                inner.end()?;
                value
            }
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for CertOrEncCert {}

impl EncodeContent for CertOrEncCert {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Certificate(inner) => inner.encoded_len(rules),
            Self::EncryptedCert(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Certificate(inner) => inner.encode(rules, out),
            Self::EncryptedCert(inner) => inner.encode(rules, out),
        }
    }
}

impl EncodeTagged for CertOrEncCert {}

impl Encode for CertOrEncCert {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Certificate(inner) => Explicit::new(&[0xa0], inner).encoded_len(rules),
            Self::EncryptedCert(inner) => Explicit::new(&[0xa1], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Certificate(inner) => Explicit::new(&[0xa0], inner).encode(rules, out),
            Self::EncryptedCert(inner) => Explicit::new(&[0xa1], inner).encode(rules, out),
        }
    }
}
