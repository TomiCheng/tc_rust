//! RFC 5652 §7 `DigestedData`.
//!
//! ```text
//! DigestedData ::= SEQUENCE {
//!     version CMSVersion,
//!     digestAlgorithm DigestAlgorithmIdentifier,
//!     encapContentInfo EncapsulatedContentInfo,
//!     digest Digest }
//! Digest ::= OCTET STRING
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::content::{ContentInfo, ContentType};

/// Content and its digest, for integrity without a signature.
///
/// The version is 0 for Data content and 2 otherwise (RFC 5652 §7); a decoded
/// version that differs is kept.
///
/// ```
/// use tc_asn1::{Asn1Any, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions, tag};
/// use tc_asn1_cms::content::{ContentInfo, ContentType, DigestedData};
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let digested = DigestedData::new(
///     AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse()?),
///     ContentInfo::new(ContentType::DATA.oid())
///         .with_content(Asn1Any::primitive(tag::OCTET_STRING, b"text")),
///     Asn1OctetString::new(&[0x11; 32]),
/// );
/// assert_eq!(digested.version(), 0.into());
/// let der = digested.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(DigestedData::decode_der(&der, &DecodingOptions::default())?.1, digested);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DigestedData {
    version: Option<Asn1Integer>,
    digest_algorithm: AlgorithmIdentifier,
    encap_content_info: ContentInfo,
    digest: Asn1OctetString,
}

impl DigestedData {
    /// Content, the algorithm that digested it, and the digest.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        digest_algorithm: AlgorithmIdentifier,
        encap_content_info: ContentInfo,
        digest: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            digest_algorithm,
            encap_content_info,
            digest,
        }
    }

    /// Returns the decoded version, or the one RFC 5652 §7 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// 0 for Data content, 2 for any other.
    fn derived_version(&self) -> Asn1Integer {
        if ContentType::from_oid(self.encap_content_info.content_type()) == Some(ContentType::DATA)
        {
            0.into()
        } else {
            2.into()
        }
    }

    /// Returns the digest algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        &self.digest_algorithm
    }

    /// Returns the encapsulated content.
    /// Variable time: branches only on the encoding structure.
    pub fn encap_content_info(&self) -> &ContentInfo {
        &self.encap_content_info
    }

    /// Returns the digest.
    /// Variable time: branches only on the encoding structure.
    pub fn digest(&self) -> &Asn1OctetString {
        &self.digest
    }
}

impl DecodeContent for DigestedData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let digest_algorithm = fields.get()?;
        let encap_content_info = fields.get()?;
        let digest = fields.get()?;
        fields.end()?;
        let mut data = Self::new(digest_algorithm, encap_content_info, digest);
        if version != data.derived_version() {
            data.version = Some(version);
        }
        Ok(data)
    }
}

impl DecodeInner for DigestedData {
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

impl EncodeContent for DigestedData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.digest_algorithm.encoded_len(rules)
            + self.encap_content_info.encoded_len(rules)
            + self.digest.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.digest_algorithm.encode(rules, &mut out[at..])?;
        at += self.encap_content_info.encode(rules, &mut out[at..])?;
        at += self.digest.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for DigestedData {}

impl Tagged for DigestedData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for DigestedData {}

impl Encode for DigestedData {
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
    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::alg::AlgorithmIdentifier;

    use super::DigestedData;
    use crate::content::{ContentInfo, ContentType};

    fn digested(content_type: tc_asn1::Asn1Oid) -> DigestedData {
        DigestedData::new(
            AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap()),
            ContentInfo::new(content_type),
            Asn1OctetString::new(&[0x11; 32]),
        )
    }

    #[test]
    fn data_content_is_version_zero_and_any_other_content_version_two() {
        assert_eq!(digested(ContentType::DATA.oid()).version(), 0.into());
        assert_eq!(digested(ContentType::SIGNED_DATA.oid()).version(), 2.into());
    }

    #[test]
    fn a_decoded_version_that_breaks_the_rule_is_kept_and_written_back() {
        let value = digested(ContentType::DATA.oid());
        let mut wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[2..5], [0x02, 0x01, 0x00]);
        wire[4] = 0x02;
        let back = DigestedData::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back.version(), 2.into());
        assert_ne!(back, value);
        assert_eq!(back.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
    }

    #[test]
    fn a_missing_digest_is_rejected() {
        let value = digested(ContentType::DATA.oid());
        let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
        let mut truncated = wire[..wire.len() - 34].to_vec();
        truncated[1] -= 34;
        assert_eq!(
            DigestedData::decode_der(&truncated, &DecodingOptions::default()),
            Err(Asn1Error::Truncated)
        );
    }
}
