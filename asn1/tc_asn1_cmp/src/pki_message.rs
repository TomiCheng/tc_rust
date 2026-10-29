//! RFC 4210 §5.1 `PKIMessage`, a CMP message.
//!
//! ```text
//! PKIMessage ::= SEQUENCE {
//!     header     PKIHeader,
//!     body       PKIBody,
//!     protection [0] PKIProtection OPTIONAL,
//!     extraCerts [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL }
//! PKIProtection ::= BIT STRING
//! ```
//!
//! The module uses explicit tags.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit,
    Tagged, tag,
};

use crate::{CmpCertificate, PkiBody, PkiHeader};

/// A header and body, the protection over both, and certificates that help
/// verify it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiMessage {
    header: PkiHeader,
    body: PkiBody,
    protection: Option<Asn1BitString>,
    extra_certs: Option<Asn1SequenceOf<CmpCertificate>>,
}

impl PkiMessage {
    /// An unprotected message without extra certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn new(header: PkiHeader, body: PkiBody) -> Self {
        Self {
            header,
            body,
            protection: None,
            extra_certs: None,
        }
    }

    /// Sets the protection over the encoded `ProtectedPart`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_protection(mut self, protection: Asn1BitString) -> Self {
        self.protection = Some(protection);
        self
    }

    /// Sets certificates that help verify the protection.
    /// Variable time: branches only on the encoding structure.
    pub fn with_extra_certs(mut self, extra_certs: Vec<CmpCertificate>) -> Self {
        self.extra_certs = Some(Asn1SequenceOf::new(extra_certs));
        self
    }

    /// Returns the header.
    /// Variable time: branches only on the encoding structure.
    pub fn header(&self) -> &PkiHeader {
        &self.header
    }

    /// Returns the body.
    /// Variable time: branches only on the encoding structure.
    pub fn body(&self) -> &PkiBody {
        &self.body
    }

    /// Returns the protection, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn protection(&self) -> Option<&Asn1BitString> {
        self.protection.as_ref()
    }

    /// Returns the extra certificates, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn extra_certs(&self) -> Option<&[CmpCertificate]> {
        self.extra_certs.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for PkiMessage {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let header = fields.get()?;
        let body = fields.get()?;
        let protection = fields.get_explicit_opt::<Asn1BitString>([0xa0])?;
        let extra_certs = fields.get_explicit_opt::<Asn1SequenceOf<CmpCertificate>>([0xa1])?;
        fields.end()?;
        let value = Self {
            header,
            body,
            protection,
            extra_certs,
        };
        Ok(value)
    }
}

impl DecodeInner for PkiMessage {
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

impl EncodeContent for PkiMessage {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.header.encoded_len(rules)
            + self.body.encoded_len(rules)
            + self
                .protection
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .extra_certs
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.header.encode(rules, out)?;
        at += self.body.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.protection {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.extra_certs {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PkiMessage {}

impl Tagged for PkiMessage {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PkiMessage {}

impl Encode for PkiMessage {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
