//! RFC 7292 4.2.4 `CRLBag`, a CRL in a PKCS #12 safe bag.
//!
//! ```text
//! CRLBag ::= SEQUENCE {
//!     crlId    BAG-TYPE.&id ({CRLTypes}),
//!     crlValue [0] EXPLICIT BAG-TYPE.&Type ({CRLTypes}{@crlId}) }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

/// The CRL type and the CRL, kept as the octets it was read with: an
/// X.509 CRL is an OCTET STRING holding its DER.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlBag {
    crl_id: Asn1Oid,
    crl_value: Asn1Any,
}

impl CrlBag {
    /// The CRL type and the CRL.
    /// Variable time: branches only on the encoding structure.
    pub fn new(crl_id: Asn1Oid, crl_value: Asn1Any) -> Self {
        Self { crl_id, crl_value }
    }

    /// Returns the CRL type, such as `x509CRL`.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_id(&self) -> &Asn1Oid {
        &self.crl_id
    }

    /// Returns the CRL.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_value(&self) -> &Asn1Any {
        &self.crl_value
    }
}

impl DecodeContent for CrlBag {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let crl_id = fields.get()?;
        let crl_value = fields.get_explicit::<Asn1Any>([0xa0])?;
        fields.end()?;
        let value = Self { crl_id, crl_value };
        Ok(value)
    }
}

impl DecodeInner for CrlBag {
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

impl EncodeContent for CrlBag {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crl_id.encoded_len(rules) + Explicit::new(&[0xa0], &self.crl_value).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.crl_id.encode(rules, out)?;
        at += Explicit::new(&[0xa0], &self.crl_value).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CrlBag {}

impl Tagged for CrlBag {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlBag {}

impl Encode for CrlBag {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
