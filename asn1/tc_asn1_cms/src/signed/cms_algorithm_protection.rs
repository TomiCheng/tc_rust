//! RFC 6211 `CMSAlgorithmProtection`, a signed attribute that binds the digest
//! and signature or MAC algorithms into what is signed.
//!
//! ```text
//! CMSAlgorithmProtection ::= SEQUENCE {
//!     digestAlgorithm         DigestAlgorithmIdentifier,
//!     signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,   -- IMPLICIT
//!     macAlgorithm        [2] MessageAuthenticationCodeAlgorithm OPTIONAL }
//!     (WITH COMPONENTS { signatureAlgorithm PRESENT, macAlgorithm ABSENT } |
//!      WITH COMPONENTS { signatureAlgorithm ABSENT, macAlgorithm PRESENT })
//! ```
//!
//! The constructors produce one of the two shapes; decoding accepts any, as
//! Bouncy Castle does, and leaves the check to the verifier.

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The algorithms a signature or MAC was made with, as the signer saw them.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::signed::CmsAlgorithmProtection;
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let protection = CmsAlgorithmProtection::signature(
///     AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse()?),
///     AlgorithmIdentifier::new("1.3.101.112".parse()?),
/// );
/// let der = protection.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(CmsAlgorithmProtection::decode_der(&der, &DecodingOptions::default())?.1, protection);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CmsAlgorithmProtection {
    digest_algorithm: AlgorithmIdentifier,
    signature_algorithm: Option<AlgorithmIdentifier>,
    mac_algorithm: Option<AlgorithmIdentifier>,
}

impl CmsAlgorithmProtection {
    /// The algorithms of a signature.
    /// Variable time: branches only on the encoding structure.
    pub fn signature(
        digest_algorithm: AlgorithmIdentifier,
        signature_algorithm: AlgorithmIdentifier,
    ) -> Self {
        Self {
            digest_algorithm,
            signature_algorithm: Some(signature_algorithm),
            mac_algorithm: None,
        }
    }

    /// The algorithms of a MAC.
    /// Variable time: branches only on the encoding structure.
    pub fn mac(digest_algorithm: AlgorithmIdentifier, mac_algorithm: AlgorithmIdentifier) -> Self {
        Self {
            digest_algorithm,
            signature_algorithm: None,
            mac_algorithm: Some(mac_algorithm),
        }
    }

    /// Returns the digest algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        &self.digest_algorithm
    }

    /// Returns the signature algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn signature_algorithm(&self) -> Option<&AlgorithmIdentifier> {
        self.signature_algorithm.as_ref()
    }

    /// Returns the MAC algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn mac_algorithm(&self) -> Option<&AlgorithmIdentifier> {
        self.mac_algorithm.as_ref()
    }
}

impl DecodeContent for CmsAlgorithmProtection {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let digest_algorithm = fields.get()?;
        let signature_algorithm = fields.get_implicit_opt([0xa1])?;
        let mac_algorithm = fields.get_implicit_opt([0xa2])?;
        fields.end()?;
        Ok(Self {
            digest_algorithm,
            signature_algorithm,
            mac_algorithm,
        })
    }
}

impl DecodeInner for CmsAlgorithmProtection {
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

impl EncodeContent for CmsAlgorithmProtection {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.digest_algorithm.encoded_len(rules)
            + self
                .signature_algorithm
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .mac_algorithm
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.digest_algorithm.encode(rules, out)?;
        if let Some(v) = &self.signature_algorithm {
            at += Implicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.mac_algorithm {
            at += Implicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CmsAlgorithmProtection {}

impl Tagged for CmsAlgorithmProtection {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CmsAlgorithmProtection {}

impl Encode for CmsAlgorithmProtection {
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
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::alg::AlgorithmIdentifier;

    use super::CmsAlgorithmProtection;

    fn alg(dotted: &str) -> AlgorithmIdentifier {
        AlgorithmIdentifier::new(dotted.parse().unwrap())
    }

    #[test]
    fn the_signature_and_mac_shapes_use_implicit_one_and_two() {
        // SHA-256 digest; Ed25519 signature; HMAC-SHA256 MAC.
        let digest = [
            0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let signature =
            CmsAlgorithmProtection::signature(alg("2.16.840.1.101.3.4.2.1"), alg("1.3.101.112"));
        let wire = signature.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            wire,
            [
                &[0x30, 0x14][..],
                &digest,
                &[0xa1, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
            ]
            .concat()
        );
        let mac =
            CmsAlgorithmProtection::mac(alg("2.16.840.1.101.3.4.2.1"), alg("1.2.840.113549.2.9"));
        let wire_mac = mac.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire_mac[2 + digest.len()], 0xa2);
        for (value, wire) in [(signature, wire), (mac, wire_mac)] {
            assert_eq!(
                CmsAlgorithmProtection::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
    }

    #[test]
    fn decoding_accepts_either_shape_but_not_the_tags_out_of_order() {
        let wire = [
            0x30, 0x0e, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa2, 0x05, 0x06, 0x03, 0x2a,
            0x03, 0x05,
        ];
        let value = CmsAlgorithmProtection::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert!(value.signature_algorithm().is_none());
        assert!(value.mac_algorithm().is_some());
        let swapped = [
            0x30, 0x15, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa2, 0x05, 0x06, 0x03, 0x2a,
            0x03, 0x05, 0xa1, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x06,
        ];
        assert_eq!(
            CmsAlgorithmProtection::decode_der(&swapped, &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }
}
