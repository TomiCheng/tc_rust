//! RFC 5126 §5.7.4.2 `OtherRevVals`, revocation values of another kind.
//!
//! ```text
//! OtherRevVals ::= SEQUENCE {
//!     otherRevValType OtherRevValType,
//!     otherRevVals    ANY DEFINED BY otherRevValType }
//! OtherRevValType ::= OBJECT IDENTIFIER
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// Revocation values by type, kept as found.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherRevVals {
    other_rev_val_type: Asn1Oid,
    other_rev_vals: Asn1Any,
}

impl OtherRevVals {
    /// The type and its value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(other_rev_val_type: Asn1Oid, other_rev_vals: Asn1Any) -> Self {
        Self {
            other_rev_val_type,
            other_rev_vals,
        }
    }

    /// Returns the type of the values.
    /// Variable time: branches only on the encoding structure.
    pub fn other_rev_val_type(&self) -> &Asn1Oid {
        &self.other_rev_val_type
    }

    /// Returns the values.
    /// Variable time: branches only on the encoding structure.
    pub fn other_rev_vals(&self) -> &Asn1Any {
        &self.other_rev_vals
    }
}

impl DecodeContent for OtherRevVals {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let other_rev_val_type = fields.get()?;
        let other_rev_vals = fields.get()?;
        fields.end()?;
        let value = Self {
            other_rev_val_type,
            other_rev_vals,
        };
        Ok(value)
    }
}

impl DecodeInner for OtherRevVals {
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

impl EncodeContent for OtherRevVals {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.other_rev_val_type.encoded_len(rules) + self.other_rev_vals.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.other_rev_val_type.encode(rules, out)?;
        at += self.other_rev_vals.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OtherRevVals {}

impl Tagged for OtherRevVals {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherRevVals {}

impl Encode for OtherRevVals {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
