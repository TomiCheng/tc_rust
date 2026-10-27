//! RFC 5083 `AuthEnvelopedData`, enveloped data under an authenticated
//! encryption algorithm such as AES-GCM.
//!
//! ```text
//! AuthEnvelopedData ::= SEQUENCE {
//!     version CMSVersion,
//!     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//!     recipientInfos RecipientInfos,
//!     authEncryptedContentInfo EncryptedContentInfo,
//!     authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
//!     mac MessageAuthenticationCode,
//!     unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit,
    Tagged, tag,
};
use tc_asn1_x500::Attribute;

use crate::content::{EncryptedContentInfo, OriginatorInfo};
use crate::recipient::RecipientInfo;

/// Content under authenticated encryption, its tag, and the key wrapped for each
/// recipient.
///
/// The version is always 0; a decoded version that differs is kept.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AuthEnvelopedData {
    version: Option<Asn1Integer>,
    originator_info: Option<OriginatorInfo>,
    recipient_infos: Asn1SetOf<RecipientInfo>,
    auth_encrypted_content_info: EncryptedContentInfo,
    auth_attrs: Option<Asn1SetOf<Attribute>>,
    mac: Asn1OctetString,
    unauth_attrs: Option<Asn1SetOf<Attribute>>,
}

impl AuthEnvelopedData {
    /// The recipients, the encrypted content and its authentication tag, without
    /// the optional fields.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        recipient_infos: Vec<RecipientInfo>,
        auth_encrypted_content_info: EncryptedContentInfo,
        mac: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            originator_info: None,
            recipient_infos: Asn1SetOf::new(recipient_infos),
            auth_encrypted_content_info,
            auth_attrs: None,
            mac,
            unauth_attrs: None,
        }
    }

    /// Adds the originator's certificates and revocation information.
    /// Variable time: branches only on the encoding structure.
    pub fn with_originator_info(mut self, originator_info: OriginatorInfo) -> Self {
        self.originator_info = Some(originator_info);
        self
    }

    /// Sets the authenticated attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn with_auth_attrs(mut self, auth_attrs: Vec<Attribute>) -> Self {
        self.auth_attrs = Some(Asn1SetOf::new(auth_attrs));
        self
    }

    /// Sets the unauthenticated attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn with_unauth_attrs(mut self, unauth_attrs: Vec<Attribute>) -> Self {
        self.unauth_attrs = Some(Asn1SetOf::new(unauth_attrs));
        self
    }

    /// Returns the decoded version, or the one RFC 5083 calls for.
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

    /// Returns the originator information, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn originator_info(&self) -> Option<&OriginatorInfo> {
        self.originator_info.as_ref()
    }

    /// Returns the recipients in construction or wire order.
    /// Variable time: branches only on the encoding structure.
    pub fn recipient_infos(&self) -> &[RecipientInfo] {
        self.recipient_infos.members()
    }

    /// Returns the encrypted content.
    /// Variable time: branches only on the encoding structure.
    pub fn auth_encrypted_content_info(&self) -> &EncryptedContentInfo {
        &self.auth_encrypted_content_info
    }

    /// Returns the authenticated attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn auth_attrs(&self) -> Option<&[Attribute]> {
        self.auth_attrs.as_ref().map(Asn1SetOf::members)
    }

    /// Returns the authentication tag.
    /// Variable time: branches only on the encoding structure.
    pub fn mac(&self) -> &Asn1OctetString {
        &self.mac
    }

    /// Returns the unauthenticated attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn unauth_attrs(&self) -> Option<&[Attribute]> {
        self.unauth_attrs.as_ref().map(Asn1SetOf::members)
    }
}

impl DecodeContent for AuthEnvelopedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let originator_info = fields.get_implicit_opt([0xa0])?;
        let recipient_infos = fields.get()?;
        let auth_encrypted_content_info = fields.get()?;
        let auth_attrs = fields.get_implicit_opt([0xa1])?;
        let mac = fields.get()?;
        let unauth_attrs = fields.get_implicit_opt([0xa2])?;
        fields.end()?;
        let mut value = Self {
            version: None,
            originator_info,
            recipient_infos,
            auth_encrypted_content_info,
            auth_attrs,
            mac,
            unauth_attrs,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for AuthEnvelopedData {
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

impl EncodeContent for AuthEnvelopedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self
                .originator_info
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self.recipient_infos.encoded_len(rules)
            + self.auth_encrypted_content_info.encoded_len(rules)
            + self
                .auth_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
            + self.mac.encoded_len(rules)
            + self
                .unauth_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        if let Some(v) = &self.originator_info {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.recipient_infos.encode(rules, &mut out[at..])?;
        at += self
            .auth_encrypted_content_info
            .encode(rules, &mut out[at..])?;
        if let Some(v) = &self.auth_attrs {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self.mac.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.unauth_attrs {
            at += Implicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for AuthEnvelopedData {}

impl Tagged for AuthEnvelopedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AuthEnvelopedData {}

impl Encode for AuthEnvelopedData {
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

    use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::AuthEnvelopedData;
    use crate::fixtures::{attribute, encrypted_content, key_trans};

    #[test]
    fn the_version_is_zero_and_every_optional_field_round_trips() {
        let value = AuthEnvelopedData::new(
            vec![key_trans().into()],
            encrypted_content(),
            Asn1OctetString::new(&[0x7a; 16]),
        )
        .with_auth_attrs(vec![attribute()])
        .with_unauth_attrs(vec![attribute()]);
        assert_eq!(value.version(), 0.into());
        for rules in [EncodingOptions::BER, EncodingOptions::DER] {
            let wire = value.encode_to_vec(&rules).unwrap();
            assert_eq!(
                AuthEnvelopedData::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }
}
