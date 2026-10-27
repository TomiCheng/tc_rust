//! RFC 5652 §6.1 `EncryptedContentInfo`, the encrypted content of enveloped,
//! encrypted and authenticated-enveloped data.
//!
//! ```text
//! EncryptedContentInfo ::= SEQUENCE {
//!     contentType ContentType,
//!     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//!     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
//! EncryptedContent ::= OCTET STRING
//! ```
//!
//! Streaming encoders write `encryptedContent` in the constructed BER form,
//! `A0` with OCTET STRING segments inside. It is accepted under BER and joined
//! into one string, and written back in the primitive form `80`.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The type of the content, how it was encrypted, and the ciphertext, which is
/// absent when it travels separately.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::content::{ContentType, EncryptedContentInfo};
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let aes128_cbc = AlgorithmIdentifier::with_parameters(
///     "2.16.840.1.101.3.4.1.2".parse()?,
///     Asn1OctetString::new(&[0; 16]),
/// );
/// let info = EncryptedContentInfo::new(ContentType::DATA.oid(), aes128_cbc)
///     .with_encrypted_content(Asn1OctetString::new(&[0xc1; 32]));
/// let der = info.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(EncryptedContentInfo::decode_der(&der, &DecodingOptions::default())?.1, info);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EncryptedContentInfo {
    content_type: Asn1Oid,
    content_encryption_algorithm: AlgorithmIdentifier,
    encrypted_content: Option<Asn1OctetString>,
}

impl EncryptedContentInfo {
    /// The content type and encryption algorithm, without the ciphertext.
    /// Variable time: branches only on the encoding structure.
    pub fn new(content_type: Asn1Oid, content_encryption_algorithm: AlgorithmIdentifier) -> Self {
        Self {
            content_type,
            content_encryption_algorithm,
            encrypted_content: None,
        }
    }

    /// Adds the ciphertext.
    /// Variable time: branches only on the encoding structure.
    pub fn with_encrypted_content(mut self, encrypted_content: Asn1OctetString) -> Self {
        self.encrypted_content = Some(encrypted_content);
        self
    }

    /// Returns the type of the content before encryption.
    /// Variable time: branches only on the encoding structure.
    pub fn content_type(&self) -> &Asn1Oid {
        &self.content_type
    }

    /// Returns the content-encryption algorithm and its parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn content_encryption_algorithm(&self) -> &AlgorithmIdentifier {
        &self.content_encryption_algorithm
    }

    /// Returns the ciphertext, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn encrypted_content(&self) -> Option<&Asn1OctetString> {
        self.encrypted_content.as_ref()
    }
}

/// The octets of an OCTET STRING under an IMPLICIT tag: the contents of the
/// primitive form, or the joined segments of the constructed one, which DER
/// forbids.
fn octets(element: &Asn1Ref<'_>, context: &mut DecodingContext) -> Result<Vec<u8>, Asn1Error> {
    if !element.is_constructed() {
        return Ok(Asn1OctetString::decode_content(element.value(), context)?
            .as_bytes()
            .to_vec());
    }
    if context.is_der() {
        return Err(Asn1Error::NotDer);
    }
    let mut joined = Vec::new();
    let mut segments = element.children(context)?;
    while let Some(segment) = segments.next() {
        let segment = segment?;
        match segment.tag() {
            [0x04] => joined.extend_from_slice(segment.value()),
            [0x24] => joined.extend(octets(&segment, segments.context())?),
            _ => return Err(Asn1Error::UnexpectedTag),
        }
    }
    Ok(joined)
}

impl DecodeContent for EncryptedContentInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let content_type = fields.get()?;
        let content_encryption_algorithm = fields.get()?;
        let encrypted_content = match fields.peek() {
            Some(Ok(element)) if matches!(element.tag(), [0x80] | [0xa0]) => {
                let element = fields.next().expect("peeked")?;
                Some(Asn1OctetString::new(&octets(&element, fields.context())?))
            }
            Some(Err(error)) => return Err(error),
            _ => None,
        };
        fields.end()?;
        Ok(Self {
            content_type,
            content_encryption_algorithm,
            encrypted_content,
        })
    }
}

impl DecodeInner for EncryptedContentInfo {
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

impl EncodeContent for EncryptedContentInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.content_type.encoded_len(rules)
            + self.content_encryption_algorithm.encoded_len(rules)
            + self
                .encrypted_content
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x80], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.content_type.encode(rules, out)?;
        at += self
            .content_encryption_algorithm
            .encode(rules, &mut out[at..])?;
        if let Some(v) = &self.encrypted_content {
            at += Implicit::new(&[0x80], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for EncryptedContentInfo {}

impl Tagged for EncryptedContentInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EncryptedContentInfo {}

impl Encode for EncryptedContentInfo {
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
    use alloc::vec::Vec;

    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::EncryptedContentInfo;
    use crate::content::ContentType;
    use crate::fixtures::alg;

    fn head() -> Vec<u8> {
        let info =
            EncryptedContentInfo::new(ContentType::DATA.oid(), alg("2.16.840.1.101.3.4.1.2"));
        let wire = info.encode_to_vec(&EncodingOptions::DER).unwrap();
        wire[2..].to_vec()
    }

    fn sequence(body: &[u8]) -> Vec<u8> {
        [&[0x30, body.len() as u8][..], body].concat()
    }

    #[test]
    fn the_ciphertext_is_a_primitive_implicit_zero_and_may_be_absent() {
        let detached =
            EncryptedContentInfo::new(ContentType::DATA.oid(), alg("2.16.840.1.101.3.4.1.2"));
        let with = detached
            .clone()
            .with_encrypted_content(Asn1OctetString::new(&[1, 2, 3]));
        let wire = with.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[wire.len() - 5..], [0x80, 0x03, 1, 2, 3]);
        for value in [detached, with] {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(
                EncryptedContentInfo::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn constructed_ber_ciphertext_segments_are_joined_but_rejected_under_der() {
        let wire = sequence(
            &[
                head(),
                // A0 80 | 04 02 01 02 | 24 80 04 01 03 00 00 | 00 00
                Vec::from([
                    0xa0, 0x80, 0x04, 0x02, 1, 2, 0x24, 0x80, 0x04, 0x01, 3, 0, 0, 0, 0,
                ]),
            ]
            .concat(),
        );
        let value = EncryptedContentInfo::decode(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(value.encrypted_content().unwrap().as_bytes(), [1, 2, 3]);
        let der = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(der[der.len() - 5..], [0x80, 0x03, 1, 2, 3]);
        assert_eq!(
            EncryptedContentInfo::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
    }

    #[test]
    fn segments_that_are_not_octet_strings_and_trailing_fields_are_rejected() {
        let bad_segment = sequence(&[head(), Vec::from([0xa0, 0x03, 0x02, 0x01, 0x01])].concat());
        assert_eq!(
            EncryptedContentInfo::decode(&bad_segment, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let trailing = sequence(&[head(), Vec::from([0x81, 0x01, 0x01])].concat());
        assert_eq!(
            EncryptedContentInfo::decode_der(&trailing, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
