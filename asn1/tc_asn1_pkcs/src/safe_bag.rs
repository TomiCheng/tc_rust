//! RFC 7292 4.2 `SafeBag`, one key, certificate, CRL or secret in a PKCS #12 file,
//! with its attributes.
//!
//! ```text
//! SafeBag ::= SEQUENCE {
//!     bagId         BAG-TYPE.&id ({PKCS12BagSet}),
//!     bagValue      [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
//!     bagAttributes SET OF PKCS12Attribute OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x500::Attribute;

/// The bag type, the bag kept as the octets it was read with, and attributes
/// such as `friendlyName` and `localKeyId`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SafeBag {
    bag_id: Asn1Oid,
    bag_value: Asn1Any,
    bag_attributes: Option<Asn1SetOf<Attribute>>,
}

impl SafeBag {
    /// The bag type and the bag, without attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn new(bag_id: Asn1Oid, bag_value: Asn1Any) -> Self {
        Self {
            bag_id,
            bag_value,
            bag_attributes: None,
        }
    }

    /// Sets the attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn with_bag_attributes(mut self, bag_attributes: Vec<Attribute>) -> Self {
        self.bag_attributes = Some(Asn1SetOf::new(bag_attributes));
        self
    }

    /// Returns the bag type, such as `pkcs8ShroudedKeyBag`.
    /// Variable time: branches only on the encoding structure.
    pub fn bag_id(&self) -> &Asn1Oid {
        &self.bag_id
    }

    /// Returns the bag.
    /// Variable time: branches only on the encoding structure.
    pub fn bag_value(&self) -> &Asn1Any {
        &self.bag_value
    }

    /// Returns the attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn bag_attributes(&self) -> Option<&[Attribute]> {
        self.bag_attributes.as_ref().map(Asn1SetOf::members)
    }
}

impl DecodeContent for SafeBag {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let bag_id = fields.get()?;
        let bag_value = fields.get_explicit::<Asn1Any>([0xa0])?;
        let bag_attributes = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            bag_id,
            bag_value,
            bag_attributes,
        };
        Ok(value)
    }
}

impl DecodeInner for SafeBag {
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

impl EncodeContent for SafeBag {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.bag_id.encoded_len(rules)
            + Explicit::new(&[0xa0], &self.bag_value).encoded_len(rules)
            + self
                .bag_attributes
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.bag_id.encode(rules, out)?;
        at += Explicit::new(&[0xa0], &self.bag_value).encode(rules, &mut out[at..])?;
        if let Some(v) = &self.bag_attributes {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SafeBag {}

impl Tagged for SafeBag {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SafeBag {}

impl Encode for SafeBag {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
