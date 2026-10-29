//! ICAO Doc 9303 part 12 `CscaMasterList`, the CSCA certificates a state trusts.
//!
//! ```text
//! CscaMasterList ::= SEQUENCE {
//!     version  CscaMasterListVersion,
//!     certList SET OF Certificate }
//! CscaMasterListVersion ::= INTEGER { v0(0) }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::cert::Certificate;

/// The country signing CA certificates of a master list.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CscaMasterList {
    version: Option<Asn1Integer>,
    cert_list: Asn1SetOf<Certificate>,
}

impl CscaMasterList {
    /// A version 0 list.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_list: Vec<Certificate>) -> Self {
        Self {
            version: None,
            cert_list: Asn1SetOf::new(cert_list),
        }
    }

    /// Returns the decoded version, or the one Doc 9303 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 0.
    fn derived_version(&self) -> Asn1Integer {
        0.into()
    }

    /// Returns the certificates in construction or wire order.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_list(&self) -> &[Certificate] {
        self.cert_list.members()
    }
}

impl DecodeContent for CscaMasterList {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let cert_list = fields.get()?;
        fields.end()?;
        let mut value = Self {
            version: None,
            cert_list,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for CscaMasterList {
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

impl EncodeContent for CscaMasterList {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules) + self.cert_list.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.cert_list.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CscaMasterList {}

impl Tagged for CscaMasterList {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CscaMasterList {}

impl Encode for CscaMasterList {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
