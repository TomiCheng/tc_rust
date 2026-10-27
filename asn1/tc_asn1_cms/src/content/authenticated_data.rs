//! RFC 5652 §9.1 `AuthenticatedData`.
//!
//! ```text
//! AuthenticatedData ::= SEQUENCE {
//!     version CMSVersion,
//!     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//!     recipientInfos RecipientInfos,
//!     macAlgorithm MessageAuthenticationCodeAlgorithm,
//!     digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,   -- IMPLICIT
//!     encapContentInfo EncapsulatedContentInfo,
//!     authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
//!     mac MessageAuthenticationCode,
//!     unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
//! MessageAuthenticationCode ::= OCTET STRING
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit,
    Tagged, tag,
};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::content::{ContentInfo, OriginatorInfo};
use crate::recipient::RecipientInfo;

/// Content with a MAC, and the MAC key wrapped for each recipient.
///
/// The version follows RFC 5652 §9.1 from the originator information; a decoded
/// version that differs is kept.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AuthenticatedData {
    version: Option<Asn1Integer>,
    originator_info: Option<OriginatorInfo>,
    recipient_infos: Asn1SetOf<RecipientInfo>,
    mac_algorithm: AlgorithmIdentifier,
    digest_algorithm: Option<AlgorithmIdentifier>,
    encap_content_info: ContentInfo,
    auth_attrs: Option<Asn1SetOf<Attribute>>,
    mac: Asn1OctetString,
    unauth_attrs: Option<Asn1SetOf<Attribute>>,
}

impl AuthenticatedData {
    /// The recipients, MAC algorithm, content and MAC, without the optional fields.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        recipient_infos: Vec<RecipientInfo>,
        mac_algorithm: AlgorithmIdentifier,
        encap_content_info: ContentInfo,
        mac: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            originator_info: None,
            recipient_infos: Asn1SetOf::new(recipient_infos),
            mac_algorithm,
            digest_algorithm: None,
            encap_content_info,
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

    /// Adds the digest algorithm, which authenticated attributes require.
    /// Variable time: branches only on the encoding structure.
    pub fn with_digest_algorithm(mut self, digest_algorithm: AlgorithmIdentifier) -> Self {
        self.digest_algorithm = Some(digest_algorithm);
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

    /// Returns the decoded version, or the one RFC 5652 §9.1 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// RFC 5652 §9.1: 3 for other certificate or revocation formats, 1 for
    /// version 2 attribute certificates, 0 otherwise.
    fn derived_version(&self) -> Asn1Integer {
        let originator = self.originator_info.as_ref();
        if originator.is_some_and(OriginatorInfo::has_other_formats) {
            3.into()
        } else if originator.is_some_and(OriginatorInfo::has_v2_attribute_certificates) {
            1.into()
        } else {
            0.into()
        }
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

    /// Returns the MAC algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn mac_algorithm(&self) -> &AlgorithmIdentifier {
        &self.mac_algorithm
    }

    /// Returns the digest algorithm of the authenticated attributes, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithm(&self) -> Option<&AlgorithmIdentifier> {
        self.digest_algorithm.as_ref()
    }

    /// Returns the encapsulated content.
    /// Variable time: branches only on the encoding structure.
    pub fn encap_content_info(&self) -> &ContentInfo {
        &self.encap_content_info
    }

    /// Returns the authenticated attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn auth_attrs(&self) -> Option<&[Attribute]> {
        self.auth_attrs.as_ref().map(Asn1SetOf::members)
    }

    /// Returns the MAC.
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

impl DecodeContent for AuthenticatedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let originator_info = fields.get_implicit_opt([0xa0])?;
        let recipient_infos = fields.get()?;
        let mac_algorithm = fields.get()?;
        let digest_algorithm = fields.get_implicit_opt([0xa1])?;
        let encap_content_info = fields.get()?;
        let auth_attrs = fields.get_implicit_opt([0xa2])?;
        let mac = fields.get()?;
        let unauth_attrs = fields.get_implicit_opt([0xa3])?;
        fields.end()?;
        let mut value = Self {
            version: None,
            originator_info,
            recipient_infos,
            mac_algorithm,
            digest_algorithm,
            encap_content_info,
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

impl DecodeInner for AuthenticatedData {
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

impl EncodeContent for AuthenticatedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self
                .originator_info
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self.recipient_infos.encoded_len(rules)
            + self.mac_algorithm.encoded_len(rules)
            + self
                .digest_algorithm
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
            + self.encap_content_info.encoded_len(rules)
            + self
                .auth_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa2], v).encoded_len(rules))
            + self.mac.encoded_len(rules)
            + self
                .unauth_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa3], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        if let Some(v) = &self.originator_info {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.recipient_infos.encode(rules, &mut out[at..])?;
        at += self.mac_algorithm.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.digest_algorithm {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self.encap_content_info.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.auth_attrs {
            at += Implicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        at += self.mac.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.unauth_attrs {
            at += Implicit::new(&[0xa3], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for AuthenticatedData {}

impl Tagged for AuthenticatedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AuthenticatedData {}

impl Encode for AuthenticatedData {
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

    use super::AuthenticatedData;
    use crate::content::{CertificateChoices, ContentInfo, ContentType, OriginatorInfo};
    use crate::fixtures::{
        alg, attribute, attribute_certificate, key_trans, other_certificate, sha256,
    };

    fn authenticated() -> AuthenticatedData {
        AuthenticatedData::new(
            vec![key_trans().into()],
            alg("1.2.840.113549.2.9"),
            ContentInfo::new(ContentType::DATA.oid()),
            Asn1OctetString::new(&[0xac; 32]),
        )
    }

    #[test]
    fn the_version_follows_the_originator_information() {
        assert_eq!(authenticated().version(), 0.into());
        let v2 = OriginatorInfo::new()
            .with_certificates(vec![CertificateChoices::from(attribute_certificate())]);
        assert_eq!(authenticated().with_originator_info(v2).version(), 1.into());
        let other = OriginatorInfo::new().with_certificates(vec![other_certificate()]);
        assert_eq!(
            authenticated().with_originator_info(other).version(),
            3.into()
        );
    }

    #[test]
    fn every_optional_field_round_trips_under_its_tag() {
        let value = authenticated()
            .with_originator_info(OriginatorInfo::new())
            .with_digest_algorithm(sha256())
            .with_auth_attrs(vec![attribute()])
            .with_unauth_attrs(vec![attribute()]);
        for rules in [EncodingOptions::BER, EncodingOptions::DER] {
            let wire = value.encode_to_vec(&rules).unwrap();
            assert_eq!(
                AuthenticatedData::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }
}
