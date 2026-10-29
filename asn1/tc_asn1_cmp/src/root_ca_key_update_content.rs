//! RFC 9480 §2.14 `RootCaKeyUpdateContent`, a root CA key update.
//!
//! ```text
//! RootCaKeyUpdateContent ::= SEQUENCE {
//!     newWithNew CMPCertificate,
//!     newWithOld [0] CMPCertificate OPTIONAL,
//!     oldWithNew [1] CMPCertificate OPTIONAL }
//! ```
//!
//! The module uses explicit tags.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::CmpCertificate;

/// The new root certificate and, optionally, the links to the old key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RootCaKeyUpdateContent {
    new_with_new: CmpCertificate,
    new_with_old: Option<CmpCertificate>,
    old_with_new: Option<CmpCertificate>,
}

impl RootCaKeyUpdateContent {
    /// The new root certificate alone.
    /// Variable time: branches only on the encoding structure.
    pub fn new(new_with_new: CmpCertificate) -> Self {
        Self {
            new_with_new,
            new_with_old: None,
            old_with_new: None,
        }
    }

    /// Sets the new key signed with the old.
    /// Variable time: branches only on the encoding structure.
    pub fn with_new_with_old(mut self, new_with_old: CmpCertificate) -> Self {
        self.new_with_old = Some(new_with_old);
        self
    }

    /// Sets the old key signed with the new.
    /// Variable time: branches only on the encoding structure.
    pub fn with_old_with_new(mut self, old_with_new: CmpCertificate) -> Self {
        self.old_with_new = Some(old_with_new);
        self
    }

    /// Returns the new key signed with itself.
    /// Variable time: branches only on the encoding structure.
    pub fn new_with_new(&self) -> &CmpCertificate {
        &self.new_with_new
    }

    /// Returns the new key signed with the old, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn new_with_old(&self) -> Option<&CmpCertificate> {
        self.new_with_old.as_ref()
    }

    /// Returns the old key signed with the new, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn old_with_new(&self) -> Option<&CmpCertificate> {
        self.old_with_new.as_ref()
    }
}

impl DecodeContent for RootCaKeyUpdateContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let new_with_new = fields.get()?;
        let new_with_old = fields.get_explicit_opt::<CmpCertificate>([0xa0])?;
        let old_with_new = fields.get_explicit_opt::<CmpCertificate>([0xa1])?;
        fields.end()?;
        let value = Self {
            new_with_new,
            new_with_old,
            old_with_new,
        };
        Ok(value)
    }
}

impl DecodeInner for RootCaKeyUpdateContent {
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

impl EncodeContent for RootCaKeyUpdateContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.new_with_new.encoded_len(rules)
            + self
                .new_with_old
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .old_with_new
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.new_with_new.encode(rules, out)?;
        if let Some(v) = &self.new_with_old {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.old_with_new {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RootCaKeyUpdateContent {}

impl Tagged for RootCaKeyUpdateContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RootCaKeyUpdateContent {}

impl Encode for RootCaKeyUpdateContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
