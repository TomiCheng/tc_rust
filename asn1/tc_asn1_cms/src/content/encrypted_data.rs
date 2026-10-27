//! RFC 5652 §8 `EncryptedData`.
//!
//! ```text
//! EncryptedData ::= SEQUENCE {
//!     version CMSVersion,
//!     encryptedContentInfo EncryptedContentInfo,
//!     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x500::Attribute;

use crate::content::EncryptedContentInfo;

/// Content encrypted under a key managed outside the message.
///
/// The version is 0 without unprotected attributes and 2 with them; a decoded
/// version that differs is kept.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EncryptedData {
    version: Option<Asn1Integer>,
    encrypted_content_info: EncryptedContentInfo,
    unprotected_attrs: Option<Asn1SetOf<Attribute>>,
}

impl EncryptedData {
    /// The encrypted content, without unprotected attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn new(encrypted_content_info: EncryptedContentInfo) -> Self {
        Self {
            version: None,
            encrypted_content_info,
            unprotected_attrs: None,
        }
    }

    /// Sets the unprotected attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn with_unprotected_attrs(mut self, unprotected_attrs: Vec<Attribute>) -> Self {
        self.unprotected_attrs = Some(Asn1SetOf::new(unprotected_attrs));
        self
    }

    /// Returns the decoded version, or the one RFC 5652 §8 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// 0 without unprotected attributes, 2 with them.
    fn derived_version(&self) -> Asn1Integer {
        if self.unprotected_attrs.is_none() {
            0.into()
        } else {
            2.into()
        }
    }

    /// Returns the encrypted content.
    /// Variable time: branches only on the encoding structure.
    pub fn encrypted_content_info(&self) -> &EncryptedContentInfo {
        &self.encrypted_content_info
    }

    /// Returns the unprotected attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn unprotected_attrs(&self) -> Option<&[Attribute]> {
        self.unprotected_attrs.as_ref().map(Asn1SetOf::members)
    }
}

impl DecodeContent for EncryptedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let encrypted_content_info = fields.get()?;
        let unprotected_attrs = fields.get_implicit_opt([0xa1])?;
        fields.end()?;
        let mut value = Self {
            version: None,
            encrypted_content_info,
            unprotected_attrs,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for EncryptedData {
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

impl EncodeContent for EncryptedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.encrypted_content_info.encoded_len(rules)
            + self
                .unprotected_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.encrypted_content_info.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.unprotected_attrs {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for EncryptedData {}

impl Tagged for EncryptedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EncryptedData {}

impl Encode for EncryptedData {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};

    use super::EncryptedData;
    use crate::fixtures::{attribute, encrypted_content};

    #[test]
    fn unprotected_attributes_raise_the_version_from_zero_to_two() {
        let plain = EncryptedData::new(encrypted_content());
        let attributed =
            EncryptedData::new(encrypted_content()).with_unprotected_attrs(vec![attribute()]);
        assert_eq!(plain.version(), 0.into());
        assert_eq!(attributed.version(), 2.into());
        for value in [plain, attributed] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                EncryptedData::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }
}
