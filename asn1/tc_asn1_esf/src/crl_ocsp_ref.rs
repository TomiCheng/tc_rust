//! RFC 5126 §5.7.4.1 `CrlOcspRef`, the revocation data for one certificate.
//!
//! ```text
//! CrlOcspRef ::= SEQUENCE {
//!     crlids   [0] CRLListID    OPTIONAL,
//!     ocspids  [1] OcspListID   OPTIONAL,
//!     otherRev [2] OtherRevRefs OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::{CrlListId, OcspListId, OtherRevRefs};

/// CRLs, OCSP responses or other data that validated one certificate.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct CrlOcspRef {
    crlids: Option<CrlListId>,
    ocspids: Option<OcspListId>,
    other_rev: Option<OtherRevRefs>,
}

impl CrlOcspRef {
    /// A reference with every field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            crlids: None,
            ocspids: None,
            other_rev: None,
        }
    }

    /// Sets the CRLs.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crlids(mut self, crlids: CrlListId) -> Self {
        self.crlids = Some(crlids);
        self
    }

    /// Sets the OCSP responses.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ocspids(mut self, ocspids: OcspListId) -> Self {
        self.ocspids = Some(ocspids);
        self
    }

    /// Sets other revocation data.
    /// Variable time: branches only on the encoding structure.
    pub fn with_other_rev(mut self, other_rev: OtherRevRefs) -> Self {
        self.other_rev = Some(other_rev);
        self
    }

    /// Returns the CRLs, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crlids(&self) -> Option<&CrlListId> {
        self.crlids.as_ref()
    }

    /// Returns the OCSP responses, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn ocspids(&self) -> Option<&OcspListId> {
        self.ocspids.as_ref()
    }

    /// Returns other revocation data, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn other_rev(&self) -> Option<&OtherRevRefs> {
        self.other_rev.as_ref()
    }
}

impl DecodeContent for CrlOcspRef {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let crlids = fields.get_explicit_opt::<CrlListId>([0xa0])?;
        let ocspids = fields.get_explicit_opt::<OcspListId>([0xa1])?;
        let other_rev = fields.get_explicit_opt::<OtherRevRefs>([0xa2])?;
        fields.end()?;
        let value = Self {
            crlids,
            ocspids,
            other_rev,
        };
        Ok(value)
    }
}

impl DecodeInner for CrlOcspRef {
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

impl EncodeContent for CrlOcspRef {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crlids
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .ocspids
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .other_rev
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.crlids {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.ocspids {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.other_rev {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CrlOcspRef {}

impl Tagged for CrlOcspRef {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlOcspRef {}

impl Encode for CrlOcspRef {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
