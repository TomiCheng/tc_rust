//! RFC 4210 §5.3.13 `CAKeyUpdAnnContent`, a CA key update announcement.
//!
//! ```text
//! CAKeyUpdAnnContent ::= SEQUENCE {
//!     oldWithNew CMPCertificate, -- old pub signed with new priv
//!     newWithOld CMPCertificate, -- new pub signed with old priv
//!     newWithNew CMPCertificate  -- new pub signed with new priv
//! }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::CmpCertificate;

/// The three certificates that link a CA's old and new keys.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CaKeyUpdAnnContent {
    old_with_new: CmpCertificate,
    new_with_old: CmpCertificate,
    new_with_new: CmpCertificate,
}

impl CaKeyUpdAnnContent {
    /// All three certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        old_with_new: CmpCertificate,
        new_with_old: CmpCertificate,
        new_with_new: CmpCertificate,
    ) -> Self {
        Self {
            old_with_new,
            new_with_old,
            new_with_new,
        }
    }

    /// Returns the old key signed with the new.
    /// Variable time: branches only on the encoding structure.
    pub fn old_with_new(&self) -> &CmpCertificate {
        &self.old_with_new
    }

    /// Returns the new key signed with the old.
    /// Variable time: branches only on the encoding structure.
    pub fn new_with_old(&self) -> &CmpCertificate {
        &self.new_with_old
    }

    /// Returns the new key signed with itself.
    /// Variable time: branches only on the encoding structure.
    pub fn new_with_new(&self) -> &CmpCertificate {
        &self.new_with_new
    }
}

impl DecodeContent for CaKeyUpdAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let old_with_new = fields.get()?;
        let new_with_old = fields.get()?;
        let new_with_new = fields.get()?;
        fields.end()?;
        let value = Self {
            old_with_new,
            new_with_old,
            new_with_new,
        };
        Ok(value)
    }
}

impl DecodeInner for CaKeyUpdAnnContent {
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

impl EncodeContent for CaKeyUpdAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.old_with_new.encoded_len(rules)
            + self.new_with_old.encoded_len(rules)
            + self.new_with_new.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.old_with_new.encode(rules, out)?;
        at += self.new_with_old.encode(rules, &mut out[at..])?;
        at += self.new_with_new.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CaKeyUpdAnnContent {}

impl Tagged for CaKeyUpdAnnContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CaKeyUpdAnnContent {}

impl Encode for CaKeyUpdAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
