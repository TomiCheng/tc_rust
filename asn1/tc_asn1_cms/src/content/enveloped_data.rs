//! RFC 5652 §6.1 `EnvelopedData`.
//!
//! ```text
//! EnvelopedData ::= SEQUENCE {
//!     version CMSVersion,
//!     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//!     recipientInfos RecipientInfos,
//!     encryptedContentInfo EncryptedContentInfo,
//!     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
//! RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
//! UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x500::Attribute;

use crate::content::{EncryptedContentInfo, OriginatorInfo};
use crate::recipient::RecipientInfo;

/// Encrypted content and the content-encryption key, wrapped for each
/// recipient.
///
/// The version follows RFC 5652 §6.1 from the originator information, the
/// recipients and the unprotected attributes; a decoded version that differs is
/// kept.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::content::{ContentType, EncryptedContentInfo, EnvelopedData};
/// use tc_asn1_cms::recipient::KeyTransRecipientInfo;
/// use tc_asn1_cms::signed::IssuerAndSerialNumber;
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let recipient = KeyTransRecipientInfo::new(
///     IssuerAndSerialNumber::new("CN=Recipient".parse()?, 2.into()).into(),
///     AlgorithmIdentifier::new("1.2.840.113549.1.1.7".parse()?), // RSAES-OAEP
///     Asn1OctetString::new(&[0x77; 256]),
/// );
/// let content = EncryptedContentInfo::new(
///     ContentType::DATA.oid(),
///     AlgorithmIdentifier::with_parameters("2.16.840.1.101.3.4.1.42".parse()?, Asn1OctetString::new(&[0; 16])),
/// )
/// .with_encrypted_content(Asn1OctetString::new(&[0xc1; 48]));
/// let enveloped = EnvelopedData::new(vec![recipient.into()], content);
/// assert_eq!(enveloped.version(), 0.into());
/// let der = enveloped.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(EnvelopedData::decode_der(&der, &DecodingOptions::default())?.1, enveloped);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EnvelopedData {
    version: Option<Asn1Integer>,
    originator_info: Option<OriginatorInfo>,
    recipient_infos: Asn1SetOf<RecipientInfo>,
    encrypted_content_info: EncryptedContentInfo,
    unprotected_attrs: Option<Asn1SetOf<Attribute>>,
}

impl EnvelopedData {
    /// The recipients and the encrypted content, without originator information or
    /// unprotected attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        recipient_infos: Vec<RecipientInfo>,
        encrypted_content_info: EncryptedContentInfo,
    ) -> Self {
        Self {
            version: None,
            originator_info: None,
            recipient_infos: Asn1SetOf::new(recipient_infos),
            encrypted_content_info,
            unprotected_attrs: None,
        }
    }

    /// Adds the originator's certificates and revocation information.
    /// Variable time: branches only on the encoding structure.
    pub fn with_originator_info(mut self, originator_info: OriginatorInfo) -> Self {
        self.originator_info = Some(originator_info);
        self
    }

    /// Sets the unprotected attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn with_unprotected_attrs(mut self, unprotected_attrs: Vec<Attribute>) -> Self {
        self.unprotected_attrs = Some(Asn1SetOf::new(unprotected_attrs));
        self
    }

    /// Returns the decoded version, or the one RFC 5652 §6.1 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// RFC 5652 §6.1, as Bouncy Castle's `CalculateVersionField`.
    fn derived_version(&self) -> Asn1Integer {
        let originator = self.originator_info.as_ref();
        if originator.is_some_and(OriginatorInfo::has_other_formats) {
            return 4.into();
        }
        if originator.is_some_and(OriginatorInfo::has_v2_attribute_certificates)
            || self
                .recipient_infos()
                .iter()
                .any(|r| matches!(r, RecipientInfo::Password(_) | RecipientInfo::Other(_)))
        {
            return 3.into();
        }
        let zero = Asn1Integer::from(0);
        if originator.is_none()
            && self.unprotected_attrs.is_none()
            && self
                .recipient_infos()
                .iter()
                .all(|r| matches!(r, RecipientInfo::KeyTrans(k) if k.version() == zero))
        {
            return zero;
        }
        2.into()
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
    pub fn encrypted_content_info(&self) -> &EncryptedContentInfo {
        &self.encrypted_content_info
    }

    /// Returns the unprotected attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn unprotected_attrs(&self) -> Option<&[Attribute]> {
        self.unprotected_attrs.as_ref().map(Asn1SetOf::members)
    }
}

impl DecodeContent for EnvelopedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let originator_info = fields.get_implicit_opt([0xa0])?;
        let recipient_infos = fields.get()?;
        let encrypted_content_info = fields.get()?;
        let unprotected_attrs = fields.get_implicit_opt([0xa1])?;
        fields.end()?;
        let mut value = Self {
            version: None,
            originator_info,
            recipient_infos,
            encrypted_content_info,
            unprotected_attrs,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for EnvelopedData {
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

impl EncodeContent for EnvelopedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self
                .originator_info
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self.recipient_infos.encoded_len(rules)
            + self.encrypted_content_info.encoded_len(rules)
            + self
                .unprotected_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        if let Some(v) = &self.originator_info {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.recipient_infos.encode(rules, &mut out[at..])?;
        at += self.encrypted_content_info.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.unprotected_attrs {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for EnvelopedData {}

impl Tagged for EnvelopedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EnvelopedData {}

impl Encode for EnvelopedData {
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

    use super::EnvelopedData;
    use crate::content::{CertificateChoices, OriginatorInfo};
    use crate::fixtures::{
        attribute, attribute_certificate, encrypted_content, kek, key_agree, key_trans,
        other_certificate, password, recipients,
    };

    fn version(data: EnvelopedData) -> tc_asn1::Asn1Integer {
        data.version()
    }

    #[test]
    fn the_version_follows_the_rfc_5652_rules_in_order() {
        let with = |r| EnvelopedData::new(vec![r], encrypted_content());
        assert_eq!(version(with(key_trans().into())), 0.into());
        assert_eq!(version(with(key_agree().into())), 2.into());
        assert_eq!(version(with(kek().into())), 2.into());
        assert_eq!(version(with(password().into())), 3.into());
        assert_eq!(
            version(with(key_trans().into()).with_unprotected_attrs(vec![attribute()])),
            2.into()
        );
        assert_eq!(
            version(with(key_trans().into()).with_originator_info(OriginatorInfo::new())),
            2.into()
        );
        let v2 = OriginatorInfo::new()
            .with_certificates(vec![CertificateChoices::from(attribute_certificate())]);
        assert_eq!(
            version(with(key_trans().into()).with_originator_info(v2)),
            3.into()
        );
        let other = OriginatorInfo::new().with_certificates(vec![other_certificate()]);
        assert_eq!(
            version(with(key_trans().into()).with_originator_info(other)),
            4.into()
        );
    }

    #[test]
    fn every_kind_of_recipient_round_trips_together_under_every_rule() {
        let value = EnvelopedData::new(recipients(), encrypted_content())
            .with_originator_info(OriginatorInfo::new())
            .with_unprotected_attrs(vec![attribute()]);
        assert_eq!(value.version(), 3.into());
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            let wire = value.encode_to_vec(&rules).unwrap();
            assert_eq!(
                EnvelopedData::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }
}
