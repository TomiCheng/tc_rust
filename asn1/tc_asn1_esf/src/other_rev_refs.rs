//! RFC 5126 §5.7.4.1 `OtherRevRefs`, revocation references of another kind.
//!
//! ```text
//! OtherRevRefs ::= SEQUENCE {
//!     otherRevRefType OtherRevRefType,
//!     otherRevRefs    ANY DEFINED BY otherRevRefType }
//! OtherRevRefType ::= OBJECT IDENTIFIER
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// Revocation references by type, kept as found.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherRevRefs {
    other_rev_ref_type: Asn1Oid,
    other_rev_refs: Asn1Any,
}

impl OtherRevRefs {
    /// The type and its value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(other_rev_ref_type: Asn1Oid, other_rev_refs: Asn1Any) -> Self {
        Self {
            other_rev_ref_type,
            other_rev_refs,
        }
    }

    /// Returns the type of the references.
    /// Variable time: branches only on the encoding structure.
    pub fn other_rev_ref_type(&self) -> &Asn1Oid {
        &self.other_rev_ref_type
    }

    /// Returns the references.
    /// Variable time: branches only on the encoding structure.
    pub fn other_rev_refs(&self) -> &Asn1Any {
        &self.other_rev_refs
    }
}

impl DecodeContent for OtherRevRefs {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let other_rev_ref_type = fields.get()?;
        let other_rev_refs = fields.get()?;
        fields.end()?;
        let value = Self {
            other_rev_ref_type,
            other_rev_refs,
        };
        Ok(value)
    }
}

impl DecodeInner for OtherRevRefs {
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

impl EncodeContent for OtherRevRefs {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.other_rev_ref_type.encoded_len(rules) + self.other_rev_refs.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.other_rev_ref_type.encode(rules, out)?;
        at += self.other_rev_refs.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OtherRevRefs {}

impl Tagged for OtherRevRefs {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherRevRefs {}

impl Encode for OtherRevRefs {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
