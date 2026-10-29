//! RFC 5126 §5.8.1 `SigPolicyQualifierInfo`, a qualifier of a signature
//! policy.
//!
//! ```text
//! SigPolicyQualifierInfo ::= SEQUENCE {
//!     sigPolicyQualifierId SigPolicyQualifierId,
//!     sigQualifier         ANY DEFINED BY sigPolicyQualifierId }
//! SigPolicyQualifierId ::= OBJECT IDENTIFIER
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A qualifier, such as the policy's URI or a user notice, kept as found.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SigPolicyQualifierInfo {
    sig_policy_qualifier_id: Asn1Oid,
    sig_qualifier: Asn1Any,
}

impl SigPolicyQualifierInfo {
    /// The qualifier type and its value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(sig_policy_qualifier_id: Asn1Oid, sig_qualifier: Asn1Any) -> Self {
        Self {
            sig_policy_qualifier_id,
            sig_qualifier,
        }
    }

    /// Returns the type of the qualifier.
    /// Variable time: branches only on the encoding structure.
    pub fn sig_policy_qualifier_id(&self) -> &Asn1Oid {
        &self.sig_policy_qualifier_id
    }

    /// Returns the qualifier.
    /// Variable time: branches only on the encoding structure.
    pub fn sig_qualifier(&self) -> &Asn1Any {
        &self.sig_qualifier
    }
}

impl DecodeContent for SigPolicyQualifierInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let sig_policy_qualifier_id = fields.get()?;
        let sig_qualifier = fields.get()?;
        fields.end()?;
        let value = Self {
            sig_policy_qualifier_id,
            sig_qualifier,
        };
        Ok(value)
    }
}

impl DecodeInner for SigPolicyQualifierInfo {
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

impl EncodeContent for SigPolicyQualifierInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.sig_policy_qualifier_id.encoded_len(rules) + self.sig_qualifier.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.sig_policy_qualifier_id.encode(rules, out)?;
        at += self.sig_qualifier.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for SigPolicyQualifierInfo {}

impl Tagged for SigPolicyQualifierInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SigPolicyQualifierInfo {}

impl Encode for SigPolicyQualifierInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
