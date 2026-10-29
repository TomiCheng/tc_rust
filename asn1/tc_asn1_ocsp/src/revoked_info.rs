//! RFC 6960 §4.2.1 `RevokedInfo`, when and why a certificate was revoked.
//!
//! ```text
//! RevokedInfo ::= SEQUENCE {
//!     revocationTime   GeneralizedTime,
//!     revocationReason [0] EXPLICIT CRLReason OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::crl::CrlReason;

/// The revocation time and, optionally, the reason.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RevokedInfo {
    revocation_time: Asn1GeneralizedTime,
    revocation_reason: Option<CrlReason>,
}

impl RevokedInfo {
    /// The revocation time, without a reason.
    /// Variable time: branches only on the encoding structure.
    pub fn new(revocation_time: Asn1GeneralizedTime) -> Self {
        Self {
            revocation_time,
            revocation_reason: None,
        }
    }

    /// Sets the reason.
    /// Variable time: branches only on the encoding structure.
    pub fn with_revocation_reason(mut self, revocation_reason: CrlReason) -> Self {
        self.revocation_reason = Some(revocation_reason);
        self
    }

    /// Returns when the certificate was revoked.
    /// Variable time: branches only on the encoding structure.
    pub fn revocation_time(&self) -> &Asn1GeneralizedTime {
        &self.revocation_time
    }

    /// Returns the reason, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn revocation_reason(&self) -> Option<&CrlReason> {
        self.revocation_reason.as_ref()
    }
}

impl DecodeContent for RevokedInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let revocation_time = fields.get()?;
        let revocation_reason = fields.get_explicit_opt::<CrlReason>([0xa0])?;
        fields.end()?;
        let value = Self {
            revocation_time,
            revocation_reason,
        };
        Ok(value)
    }
}

impl DecodeInner for RevokedInfo {
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

impl EncodeContent for RevokedInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.revocation_time.encoded_len(rules)
            + self
                .revocation_reason
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.revocation_time.encode(rules, out)?;
        if let Some(v) = &self.revocation_reason {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RevokedInfo {}

impl Tagged for RevokedInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RevokedInfo {}

impl Encode for RevokedInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
