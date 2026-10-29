//! ICAO Doc 9303 part 10 `DataGroupHash`, the hash of one data group.
//!
//! ```text
//! DataGroupHash ::= SEQUENCE {
//!     dataGroupNumber    DataGroupNumber,
//!     dataGroupHashValue OCTET STRING }
//! DataGroupNumber ::= INTEGER { dataGroup1 (1), ..., dataGroup16 (16) }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A data group number, 1 to 16, and the hash of its contents.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DataGroupHash {
    data_group_number: Asn1Integer,
    data_group_hash_value: Asn1OctetString,
}

impl DataGroupHash {
    /// The data group number and its hash.
    /// Variable time: branches only on the encoding structure.
    pub fn new(data_group_number: Asn1Integer, data_group_hash_value: Asn1OctetString) -> Self {
        Self {
            data_group_number,
            data_group_hash_value,
        }
    }

    /// Returns the data group number.
    /// Variable time: branches only on the encoding structure.
    pub fn data_group_number(&self) -> &Asn1Integer {
        &self.data_group_number
    }

    /// Returns the hash of the data group.
    /// Variable time: branches only on the encoding structure.
    pub fn data_group_hash_value(&self) -> &Asn1OctetString {
        &self.data_group_hash_value
    }
}

impl DecodeContent for DataGroupHash {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let data_group_number = fields.get()?;
        let data_group_hash_value = fields.get()?;
        fields.end()?;
        let value = Self {
            data_group_number,
            data_group_hash_value,
        };
        Ok(value)
    }
}

impl DecodeInner for DataGroupHash {
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

impl EncodeContent for DataGroupHash {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.data_group_number.encoded_len(rules) + self.data_group_hash_value.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.data_group_number.encode(rules, out)?;
        at += self.data_group_hash_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for DataGroupHash {}

impl Tagged for DataGroupHash {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for DataGroupHash {}

impl Encode for DataGroupHash {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
