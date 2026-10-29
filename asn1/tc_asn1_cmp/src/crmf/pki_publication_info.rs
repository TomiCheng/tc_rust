//! RFC 4211 §6.3 `PKIPublicationInfo`, the value of the pkiPublicationInfo control.
//!
//! ```text
//! PKIPublicationInfo ::= SEQUENCE {
//!     action   INTEGER { dontPublish (0), pleasePublish (1) },
//!     pubInfos SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::crmf::SinglePubInfo;

/// Whether and where the CA should publish the certificate.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiPublicationInfo {
    action: Asn1Integer,
    pub_infos: Option<Asn1SequenceOf<SinglePubInfo>>,
}

impl PkiPublicationInfo {
    /// An action without publication details.
    /// Variable time: branches only on the encoding structure.
    pub fn new(action: Asn1Integer) -> Self {
        Self {
            action,
            pub_infos: None,
        }
    }

    /// Sets where to publish.
    /// Variable time: branches only on the encoding structure.
    pub fn with_pub_infos(mut self, pub_infos: Vec<SinglePubInfo>) -> Self {
        self.pub_infos = Some(Asn1SequenceOf::new(pub_infos));
        self
    }

    /// Returns the action: 0 dontPublish, 1 pleasePublish.
    /// Variable time: branches only on the encoding structure.
    pub fn action(&self) -> &Asn1Integer {
        &self.action
    }

    /// Returns where to publish, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn pub_infos(&self) -> Option<&[SinglePubInfo]> {
        self.pub_infos.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for PkiPublicationInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let action = fields.get()?;
        let pub_infos = fields.get_opt()?;
        fields.end()?;
        let value = Self { action, pub_infos };
        Ok(value)
    }
}

impl DecodeInner for PkiPublicationInfo {
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

impl EncodeContent for PkiPublicationInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.action.encoded_len(rules) + self.pub_infos.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.action.encode(rules, out)?;
        if let Some(v) = &self.pub_infos {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PkiPublicationInfo {}

impl Tagged for PkiPublicationInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PkiPublicationInfo {}

impl Encode for PkiPublicationInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
