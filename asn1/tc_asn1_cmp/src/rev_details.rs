//! RFC 4210 §5.3.9 `RevDetails`, one certificate to revoke.
//!
//! ```text
//! RevDetails ::= SEQUENCE {
//!     certDetails     CertTemplate,
//!     crlEntryDetails Extensions OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;

use crate::crmf::CertTemplate;

/// The certificate to revoke and the CRL entry extensions asked for.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RevDetails {
    cert_details: CertTemplate,
    crl_entry_details: Option<Extensions>,
}

impl RevDetails {
    /// The certificate, without CRL entry extensions.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_details: CertTemplate) -> Self {
        Self {
            cert_details,
            crl_entry_details: None,
        }
    }

    /// Sets the CRL entry extensions, such as the reason.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_entry_details(mut self, crl_entry_details: Extensions) -> Self {
        self.crl_entry_details = Some(crl_entry_details);
        self
    }

    /// Returns the certificate, as a template.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_details(&self) -> &CertTemplate {
        &self.cert_details
    }

    /// Returns the CRL entry extensions, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_entry_details(&self) -> Option<&Extensions> {
        self.crl_entry_details.as_ref()
    }
}

impl DecodeContent for RevDetails {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_details = fields.get()?;
        let crl_entry_details = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            cert_details,
            crl_entry_details,
        };
        Ok(value)
    }
}

impl DecodeInner for RevDetails {
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

impl EncodeContent for RevDetails {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_details.encoded_len(rules)
            + self
                .crl_entry_details
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_details.encode(rules, out)?;
        if let Some(v) = &self.crl_entry_details {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RevDetails {}

impl Tagged for RevDetails {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RevDetails {}

impl Encode for RevDetails {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
