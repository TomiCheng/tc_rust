//! RFC 5126 §5.8.1 `SignaturePolicyId`, an explicit signature policy.
//!
//! ```text
//! SignaturePolicyId ::= SEQUENCE {
//!     sigPolicyId         SigPolicyId,
//!     sigPolicyHash       SigPolicyHash,
//!     sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL }
//! SigPolicyId ::= OBJECT IDENTIFIER
//! SigPolicyHash ::= OtherHashAlgAndValue
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{OtherHashAlgAndValue, SigPolicyQualifierInfo};

/// The policy, the hash of its document, and qualifiers such as where to find it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignaturePolicyId {
    sig_policy_identifier: Asn1Oid,
    sig_policy_hash: OtherHashAlgAndValue,
    sig_policy_qualifiers: Option<Asn1SequenceOf<SigPolicyQualifierInfo>>,
}

impl SignaturePolicyId {
    /// The policy and its hash, without qualifiers.
    /// Variable time: branches only on the encoding structure.
    pub fn new(sig_policy_identifier: Asn1Oid, sig_policy_hash: OtherHashAlgAndValue) -> Self {
        Self {
            sig_policy_identifier,
            sig_policy_hash,
            sig_policy_qualifiers: None,
        }
    }

    /// Sets the qualifiers.
    /// Variable time: branches only on the encoding structure.
    pub fn with_sig_policy_qualifiers(
        mut self,
        sig_policy_qualifiers: Vec<SigPolicyQualifierInfo>,
    ) -> Self {
        self.sig_policy_qualifiers = Some(Asn1SequenceOf::new(sig_policy_qualifiers));
        self
    }

    /// Returns the policy.
    /// Variable time: branches only on the encoding structure.
    pub fn sig_policy_identifier(&self) -> &Asn1Oid {
        &self.sig_policy_identifier
    }

    /// Returns the hash of the policy document.
    /// Variable time: branches only on the encoding structure.
    pub fn sig_policy_hash(&self) -> &OtherHashAlgAndValue {
        &self.sig_policy_hash
    }

    /// Returns the qualifiers, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn sig_policy_qualifiers(&self) -> Option<&[SigPolicyQualifierInfo]> {
        self.sig_policy_qualifiers
            .as_ref()
            .map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for SignaturePolicyId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let sig_policy_identifier = fields.get()?;
        let sig_policy_hash = fields.get()?;
        let sig_policy_qualifiers = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            sig_policy_identifier,
            sig_policy_hash,
            sig_policy_qualifiers,
        };
        Ok(value)
    }
}

impl DecodeInner for SignaturePolicyId {
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

impl EncodeContent for SignaturePolicyId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.sig_policy_identifier.encoded_len(rules)
            + self.sig_policy_hash.encoded_len(rules)
            + self
                .sig_policy_qualifiers
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.sig_policy_identifier.encode(rules, out)?;
        at += self.sig_policy_hash.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.sig_policy_qualifiers {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SignaturePolicyId {}

impl Tagged for SignaturePolicyId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SignaturePolicyId {}

impl Encode for SignaturePolicyId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
