//! RFC 5652 §5.3 `SignerInfo`, one signer's signature and attributes.
//!
//! ```text
//! SignerInfo ::= SEQUENCE {
//!     version CMSVersion,
//!     sid SignerIdentifier,
//!     digestAlgorithm DigestAlgorithmIdentifier,
//!     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//!     signatureAlgorithm SignatureAlgorithmIdentifier,
//!     signature SignatureValue,
//!     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//! SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//! SignatureValue ::= OCTET STRING
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Oid, Asn1Ref, Asn1SetOf, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::signed::SignerIdentifier;

/// One signer: which certificate, which algorithms, the signature, and the
/// signed and unsigned attributes.
///
/// The version follows the signer identifier, 1 for issuer and serial number
/// and 3 for a key identifier, unless [`with_version`](Self::with_version)
/// pins another; a decoded version that differs from that rule is kept.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::signed::{IssuerAndSerialNumber, SignerInfo};
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let signer = SignerInfo::new(
///     IssuerAndSerialNumber::new("CN=Signer".parse()?, 1.into()).into(),
///     AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse()?), // SHA-256
///     AlgorithmIdentifier::new("1.3.101.112".parse()?),           // Ed25519
///     Asn1OctetString::new(&[0x5a; 64]),
/// );
/// assert_eq!(signer.version(), 1.into());
/// let der = signer.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(SignerInfo::decode_der(&der, &DecodingOptions::default())?.1, signer);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignerInfo {
    version: Option<Asn1Integer>,
    sid: SignerIdentifier,
    digest_algorithm: AlgorithmIdentifier,
    signed_attrs: Option<Asn1SetOf<Attribute>>,
    signature_algorithm: AlgorithmIdentifier,
    signature: Asn1OctetString,
    unsigned_attrs: Option<Asn1SetOf<Attribute>>,
}

impl SignerInfo {
    /// A signer without attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        sid: SignerIdentifier,
        digest_algorithm: AlgorithmIdentifier,
        signature_algorithm: AlgorithmIdentifier,
        signature: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            sid,
            digest_algorithm,
            signed_attrs: None,
            signature_algorithm,
            signature,
            unsigned_attrs: None,
        }
    }

    /// Sets the signed attributes, over which the signature is computed.
    /// Variable time: branches only on the encoding structure.
    pub fn with_signed_attrs(mut self, attributes: Vec<Attribute>) -> Self {
        self.signed_attrs = Some(Asn1SetOf::new(attributes));
        self
    }

    /// Sets the unsigned attributes, such as countersignatures.
    /// Variable time: branches only on the encoding structure.
    pub fn with_unsigned_attrs(mut self, attributes: Vec<Attribute>) -> Self {
        self.unsigned_attrs = Some(Asn1SetOf::new(attributes));
        self
    }

    /// Pins the version instead of deriving it from the signer identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_version(mut self, version: Asn1Integer) -> Self {
        self.version = Some(version);
        self
    }

    /// Returns the pinned or decoded version, or the one the signer identifier
    /// calls for. Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// RFC 5652 §5.3: 1 for issuer and serial number, 3 for a key identifier.
    fn derived_version(&self) -> Asn1Integer {
        match self.sid {
            SignerIdentifier::IssuerAndSerialNumber(_) => 1.into(),
            SignerIdentifier::SubjectKeyIdentifier(_) => 3.into(),
        }
    }

    /// Returns the signer identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn sid(&self) -> &SignerIdentifier {
        &self.sid
    }

    /// Returns the digest algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        &self.digest_algorithm
    }

    /// Returns the signed attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn signed_attrs(&self) -> Option<&[Attribute]> {
        self.signed_attrs.as_ref().map(Asn1SetOf::members)
    }

    /// Returns the first signed attribute of `attribute_type`, as Bouncy
    /// Castle's `AttributeTable` does. Variable time: branches only on the
    /// encoding structure.
    pub fn signed_attr(&self, attribute_type: &Asn1Oid) -> Option<&Attribute> {
        find(self.signed_attrs(), attribute_type)
    }

    /// The octets the signature covers when signed attributes are present: their
    /// DER encoding under the universal SET tag rather than `[0]`, as RFC 5652
    /// §5.4 specifies. `None` without signed attributes, where the signature
    /// covers the content's digest instead. Variable time: branches only on the
    /// encoding structure.
    pub fn signed_attrs_der(&self) -> Result<Option<Vec<u8>>, Asn1Error> {
        self.signed_attrs
            .as_ref()
            .map(|set| set.encode_to_vec(&EncodingOptions::DER))
            .transpose()
    }

    /// Returns the signature algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature value.
    /// Variable time: branches only on the encoding structure.
    pub fn signature(&self) -> &Asn1OctetString {
        &self.signature
    }

    /// Returns the unsigned attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn unsigned_attrs(&self) -> Option<&[Attribute]> {
        self.unsigned_attrs.as_ref().map(Asn1SetOf::members)
    }

    /// Returns the first unsigned attribute of `attribute_type`.
    /// Variable time: branches only on the encoding structure.
    pub fn unsigned_attr(&self, attribute_type: &Asn1Oid) -> Option<&Attribute> {
        find(self.unsigned_attrs(), attribute_type)
    }
}

fn find<'a>(
    attributes: Option<&'a [Attribute]>,
    attribute_type: &Asn1Oid,
) -> Option<&'a Attribute> {
    attributes?
        .iter()
        .find(|attribute| attribute.attribute_type() == attribute_type)
}

impl DecodeContent for SignerInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let sid = fields.get()?;
        let digest_algorithm = fields.get()?;
        let signed_attrs = fields.get_implicit_opt([0xa0])?;
        let signature_algorithm = fields.get()?;
        let signature = fields.get()?;
        let unsigned_attrs = fields.get_implicit_opt([0xa1])?;
        fields.end()?;
        let mut info = Self {
            version: None,
            sid,
            digest_algorithm,
            signed_attrs,
            signature_algorithm,
            signature,
            unsigned_attrs,
        };
        if version != info.derived_version() {
            info.version = Some(version);
        }
        Ok(info)
    }
}

impl DecodeInner for SignerInfo {
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

impl EncodeContent for SignerInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.sid.encoded_len(rules)
            + self.digest_algorithm.encoded_len(rules)
            + self
                .signed_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self.signature_algorithm.encoded_len(rules)
            + self.signature.encoded_len(rules)
            + self
                .unsigned_attrs
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.sid.encode(rules, &mut out[at..])?;
        at += self.digest_algorithm.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.signed_attrs {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.signature_algorithm.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.unsigned_attrs {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SignerInfo {}

impl Tagged for SignerInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SignerInfo {}

impl Encode for SignerInfo {
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

    use tc_asn1::{
        Asn1Error, Asn1Integer, Asn1OctetString, Asn1Oid, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };
    use tc_asn1_x500::{Attribute, AttributeValue};

    use super::SignerInfo;
    use crate::fixtures::{by_issuer, by_key_identifier};
    use crate::signed::{CmsAttribute, SignerIdentifier};

    fn attribute(oid: &Asn1Oid, octets: &[u8]) -> Attribute {
        let value = AttributeValue::from(tc_asn1::Asn1Object::OctetString(Asn1OctetString::new(
            octets,
        )));
        Attribute::new(oid.clone(), vec![value]).unwrap()
    }

    #[test]
    fn the_version_follows_the_signer_identifier_unless_pinned() {
        assert_eq!(by_issuer().version(), Asn1Integer::from(1));
        assert_eq!(by_key_identifier().version(), Asn1Integer::from(3));
        let pinned = by_issuer().with_version(4.into());
        assert_eq!(pinned.version(), Asn1Integer::from(4));
        let wire = pinned.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[2..5], [0x02, 0x01, 0x04]);
        assert_eq!(
            SignerInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            pinned
        );
    }

    #[test]
    fn signed_and_unsigned_attributes_round_trip_and_are_found_by_type() {
        let digest = CmsAttribute::MESSAGE_DIGEST.oid();
        let content_type = CmsAttribute::CONTENT_TYPE.oid();
        let signer = by_key_identifier()
            .with_signed_attrs(vec![
                attribute(&digest, &[1; 32]),
                attribute(&content_type, &[2]),
            ])
            .with_unsigned_attrs(vec![attribute(&CmsAttribute::COUNTERSIGNATURE.oid(), &[3])]);
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::DER,
            EncodingOptions::CER,
        ] {
            let wire = signer.encode_to_vec(&rules).unwrap();
            assert_eq!(
                SignerInfo::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                signer
            );
        }
        assert_eq!(
            signer.signed_attr(&digest).unwrap().attribute_type(),
            &digest
        );
        assert!(
            signer
                .signed_attr(&CmsAttribute::SIGNING_TIME.oid())
                .is_none()
        );
        assert!(
            signer
                .unsigned_attr(&CmsAttribute::COUNTERSIGNATURE.oid())
                .is_some()
        );
    }

    #[test]
    fn the_signed_octets_are_the_der_set_with_its_universal_tag() {
        assert_eq!(by_issuer().signed_attrs_der().unwrap(), None);
        let signer = by_issuer().with_signed_attrs(vec![
            attribute(&CmsAttribute::MESSAGE_DIGEST.oid(), &[1; 32]),
            attribute(&CmsAttribute::CONTENT_TYPE.oid(), &[2]),
        ]);
        let signed = signer.signed_attrs_der().unwrap().unwrap();
        assert_eq!(signed[0], 0x31);
        // Under DER the shorter contentType attribute sorts first.
        let in_message = signer.encode_to_vec(&EncodingOptions::DER).unwrap();
        let at = in_message.iter().position(|&b| b == 0xa0).unwrap();
        assert_eq!(in_message[at + 1..at + signed.len()], signed[1..]);
    }

    #[test]
    fn a_missing_signature_or_attributes_under_another_tag_are_rejected() {
        let der = |value: &dyn Encode| value.encode_to_vec(&EncodingOptions::DER).unwrap();
        let signer = by_issuer();
        let head = [
            der(&signer.version()),
            der(signer.sid()),
            der(signer.digest_algorithm()),
        ]
        .concat();
        let sequence = |body: &[u8]| [&[0x30, body.len() as u8][..], body].concat();

        let unsigned = sequence(&[head.clone(), der(signer.signature_algorithm())].concat());
        assert_eq!(
            SignerInfo::decode_der(&unsigned, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
        let wrong_tag = sequence(
            &[
                head,
                vec![0xa2, 0x00],
                der(signer.signature_algorithm()),
                der(signer.signature()),
            ]
            .concat(),
        );
        assert_eq!(
            SignerInfo::decode_der(&wrong_tag, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn signer_identifiers_of_both_kinds_survive_a_round_trip() {
        for signer in [by_issuer(), by_key_identifier()] {
            let wire = signer.encode_to_vec(&EncodingOptions::DER).unwrap();
            let back = SignerInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(back, signer);
            assert!(matches!(
                (back.sid(), signer.sid()),
                (
                    SignerIdentifier::IssuerAndSerialNumber(_),
                    SignerIdentifier::IssuerAndSerialNumber(_)
                ) | (
                    SignerIdentifier::SubjectKeyIdentifier(_),
                    SignerIdentifier::SubjectKeyIdentifier(_)
                )
            ));
        }
    }
}
