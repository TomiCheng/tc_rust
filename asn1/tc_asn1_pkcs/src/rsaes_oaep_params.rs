//! RFC 8017 A.2.1 RSAES-OAEP parameters.
//!
//! ```text
//! RSAES-OAEP-params ::= SEQUENCE {
//!     hashAlgorithm    [0] HashAlgorithm    DEFAULT sha1,
//!     maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
//!     pSourceAlgorithm [2] PSourceAlgorithm DEFAULT pSpecifiedEmpty }
//! ```
//!
//! All context tags are EXPLICIT. Defaults include the SHA-1 identifier's NULL
//! parameters; absent parameters are a distinct value. Written defaults are
//! accepted under BER and rejected under DER. Encoding omits exact defaults.
//! Algorithm suitability is left to the caller.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::AlgorithmIdentifier;

use crate::rsa_defaults;

/// OAEP hash, mask and label-source parameters.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_pkcs::RsaesOaepParams;
///
/// let params = RsaesOaepParams::default_params();
/// assert_eq!(params.encode_to_vec(&EncodingOptions::DER)?, [0x30, 0]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RsaesOaepParams {
    hash_algorithm: AlgorithmIdentifier,
    mask_gen_algorithm: AlgorithmIdentifier,
    p_source_algorithm: AlgorithmIdentifier,
}

impl RsaesOaepParams {
    /// Stores the algorithms without imposing algorithm policy.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        hash_algorithm: AlgorithmIdentifier,
        mask_gen_algorithm: AlgorithmIdentifier,
        p_source_algorithm: AlgorithmIdentifier,
    ) -> Self {
        Self {
            hash_algorithm,
            mask_gen_algorithm,
            p_source_algorithm,
        }
    }

    /// Returns SHA-1 with explicit NULL parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn sha1() -> AlgorithmIdentifier {
        rsa_defaults::sha1()
    }

    /// Returns MGF1 with the SHA-1 identifier, including its NULL parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn mgf1_sha1() -> AlgorithmIdentifier {
        rsa_defaults::mgf1_sha1()
    }

    /// Returns pSpecified with an empty OCTET STRING label.
    /// Variable time: branches only on the encoding structure.
    pub fn p_specified_empty() -> AlgorithmIdentifier {
        rsa_defaults::p_specified_empty()
    }

    /// Returns the exact RFC 8017 defaults.
    /// Variable time: branches only on the encoding structure.
    pub fn default_params() -> Self {
        Self {
            hash_algorithm: Self::sha1(),
            mask_gen_algorithm: Self::mgf1_sha1(),
            p_source_algorithm: Self::p_specified_empty(),
        }
    }

    /// Returns the hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// Returns the mask gen algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn mask_gen_algorithm(&self) -> &AlgorithmIdentifier {
        &self.mask_gen_algorithm
    }

    /// Returns the p source algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn p_source_algorithm(&self) -> &AlgorithmIdentifier {
        &self.p_source_algorithm
    }
}

impl Default for RsaesOaepParams {
    /// Variable time: branches only on the encoding structure.
    fn default() -> Self {
        Self::default_params()
    }
}

impl fmt::Display for RsaesOaepParams {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hash algorithm: {}, mask gen algorithm: {}, p source algorithm: {}",
            self.hash_algorithm, self.mask_gen_algorithm, self.p_source_algorithm
        )
    }
}

impl DecodeInner for RsaesOaepParams {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let hash_algorithm = fields.get_explicit_default([0xa0], Self::sha1())?;
        let mask_gen_algorithm = fields.get_explicit_default([0xa1], Self::mgf1_sha1())?;
        let p_source_algorithm = fields.get_explicit_default([0xa2], Self::p_specified_empty())?;
        fields.end()?;
        Ok((
            element.total_len(),
            Self::new(hash_algorithm, mask_gen_algorithm, p_source_algorithm),
        ))
    }
}

impl EncodeContent for RsaesOaepParams {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = 0;
        if !rsa_defaults::is_sha1(&self.hash_algorithm) {
            len += Explicit::new(&[0xa0], &self.hash_algorithm).encoded_len(rules);
        }
        if !rsa_defaults::is_mgf1_sha1(&self.mask_gen_algorithm) {
            len += Explicit::new(&[0xa1], &self.mask_gen_algorithm).encoded_len(rules);
        }
        if !rsa_defaults::is_p_specified_empty(&self.p_source_algorithm) {
            len += Explicit::new(&[0xa2], &self.p_source_algorithm).encoded_len(rules);
        }
        len
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if !rsa_defaults::is_sha1(&self.hash_algorithm) {
            at += Explicit::new(&[0xa0], &self.hash_algorithm).encode(rules, &mut out[at..])?;
        }
        if !rsa_defaults::is_mgf1_sha1(&self.mask_gen_algorithm) {
            at += Explicit::new(&[0xa1], &self.mask_gen_algorithm).encode(rules, &mut out[at..])?;
        }
        if !rsa_defaults::is_p_specified_empty(&self.p_source_algorithm) {
            at += Explicit::new(&[0xa2], &self.p_source_algorithm).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RsaesOaepParams {}

impl Tagged for RsaesOaepParams {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RsaesOaepParams {}

impl Encode for RsaesOaepParams {
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
    use alloc::{string::ToString, vec, vec::Vec};

    use tc_asn1::{
        Asn1Error, Asn1Null, Asn1Object, Asn1OctetString, Decode, DecodingOptions, Encode,
        EncodeContent, EncodingOptions, Explicit,
    };
    use tc_asn1_x509::AlgorithmIdentifier;

    use crate::Pkcs1Algorithm;

    use super::RsaesOaepParams;

    fn sequence(content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128);
        let mut wire = vec![0x30, content.len() as u8];
        wire.extend_from_slice(content);
        wire
    }

    #[test]
    fn oaep_defaults_encode_as_an_empty_sequence_and_preserve_exact_parameters() {
        let params = RsaesOaepParams::default_params();
        assert_eq!(params, RsaesOaepParams::default());
        assert_eq!(params.hash_algorithm(), &RsaesOaepParams::sha1());
        assert_eq!(params.mask_gen_algorithm(), &RsaesOaepParams::mgf1_sha1());
        assert_eq!(
            params.p_source_algorithm(),
            &RsaesOaepParams::p_specified_empty()
        );
        assert_eq!(
            params.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0x30, 0]
        );
        assert_eq!(
            RsaesOaepParams::decode_der(&[0x30, 0], &DecodingOptions::default())
                .unwrap()
                .1,
            params
        );
        assert!(
            params
                .to_string()
                .contains("hash algorithm: 1.3.14.3.2.26 NULL")
        );
        assert_eq!(
            RsaesOaepParams::sha1()
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            [0x30, 9, 6, 5, 0x2b, 0x0e, 3, 2, 0x1a, 5, 0],
        );
        assert_eq!(
            RsaesOaepParams::mgf1_sha1()
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            [
                0x30, 0x16, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 8, 0x30, 9, 6, 5, 0x2b,
                0x0e, 3, 2, 0x1a, 5, 0
            ],
        );
        assert_eq!(
            RsaesOaepParams::p_specified_empty()
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            [
                0x30, 0x0d, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 9, 4, 0
            ],
        );
    }

    #[test]
    fn every_explicit_oaep_default_is_accepted_under_ber_and_rejected_under_der() {
        let defaults = RsaesOaepParams::default_params();
        let mut together = Vec::new();
        for content in [
            Explicit::new(&[0xa0], defaults.hash_algorithm())
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            Explicit::new(&[0xa1], defaults.mask_gen_algorithm())
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            Explicit::new(&[0xa2], defaults.p_source_algorithm())
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
        ] {
            let wire = sequence(&content);
            assert_eq!(
                RsaesOaepParams::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                defaults
            );
            assert_eq!(
                RsaesOaepParams::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::NotDer)
            );
            together.extend_from_slice(&content);
        }
        let wire = sequence(&together);
        assert_eq!(
            RsaesOaepParams::decode(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            defaults
        );
        assert_eq!(
            RsaesOaepParams::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
    }

    #[test]
    fn nondefault_oaep_hashes_are_explicitly_wrapped_and_round_trip_under_all_rules() {
        let hash = AlgorithmIdentifier::with_null(Pkcs1Algorithm::SHA256.oid());
        let params = RsaesOaepParams::new(
            hash,
            RsaesOaepParams::mgf1_sha1(),
            RsaesOaepParams::p_specified_empty(),
        );
        let expected = [
            0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1, 5, 0,
        ];
        assert_eq!(
            params.encode_to_vec(&EncodingOptions::DER).unwrap(),
            expected
        );
        assert_eq!(
            RsaesOaepParams::decode_der(&expected, &DecodingOptions::default())
                .unwrap()
                .1,
            params
        );
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::CER,
            EncodingOptions::DER,
        ] {
            let wire = params.encode_to_vec(&rules).unwrap();
            assert_eq!(wire.len(), params.encoded_len(&rules));
            assert_eq!(
                RsaesOaepParams::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                params
            );
            let mut content = vec![0; params.content_len(&rules)];
            assert_eq!(
                params.encode_content(&rules, &mut content).unwrap(),
                content.len()
            );
        }
    }

    #[test]
    fn absent_hash_and_nested_mask_parameters_are_not_confused_with_null_defaults() {
        let hash = AlgorithmIdentifier::new(Pkcs1Algorithm::SHA1.oid());
        let mask = AlgorithmIdentifier::with_parameters(
            Pkcs1Algorithm::MGF1.oid(),
            Asn1Object::sequence(vec![Pkcs1Algorithm::SHA1.oid().into()]),
        );
        let params = RsaesOaepParams::new(hash, mask, RsaesOaepParams::p_specified_empty());
        let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert!(wire.contains(&0xa0));
        assert!(wire.contains(&0xa1));
        assert_eq!(
            RsaesOaepParams::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            params
        );
        for mask in [
            AlgorithmIdentifier::new(Pkcs1Algorithm::MGF1.oid()),
            AlgorithmIdentifier::with_null(Pkcs1Algorithm::MGF1.oid()),
            AlgorithmIdentifier::with_parameters(
                Pkcs1Algorithm::MGF1.oid(),
                Asn1Object::sequence(vec![Pkcs1Algorithm::SHA256.oid().into(), Asn1Null.into()]),
            ),
            AlgorithmIdentifier::with_null("1.2.3.4".parse().unwrap()),
        ] {
            let params = RsaesOaepParams::new(
                RsaesOaepParams::sha1(),
                mask,
                RsaesOaepParams::p_specified_empty(),
            );
            let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(wire[2], 0xa1);
            assert_eq!(
                RsaesOaepParams::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                params
            );
        }
    }

    #[test]
    fn oaep_fields_require_explicit_wrappers_and_schema_order() {
        let implicit = [0x30, 0x0b, 0xa0, 9, 6, 5, 0x2b, 0x0e, 3, 2, 0x1a, 5, 0];
        assert_eq!(
            RsaesOaepParams::decode_der(&implicit, &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
        let nondefault = AlgorithmIdentifier::new(Pkcs1Algorithm::SHA256.oid());
        let a0 = Explicit::new(&[0xa0], &nondefault)
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        let a1 = Explicit::new(&[0xa1], &nondefault)
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        for (first, second) in [(&a0, &a0), (&a1, &a0)] {
            let mut content = first.clone();
            content.extend_from_slice(second);
            assert_eq!(
                RsaesOaepParams::decode_der(&sequence(&content), &DecodingOptions::default()),
                Err(Asn1Error::TrailingData)
            );
        }
        for (wire, error) in [
            (&[0x31, 0][..], Asn1Error::UnexpectedTag),
            (&[0x30, 2, 0xa0, 0][..], Asn1Error::Truncated),
            (&[0x30, 2, 5, 0][..], Asn1Error::TrailingData),
        ] {
            assert_eq!(
                RsaesOaepParams::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
        let mut content = a0;
        content[1] += 2;
        content.extend_from_slice(&[5, 0]);
        assert_eq!(
            RsaesOaepParams::decode_der(&sequence(&content), &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }

    #[test]
    fn oaep_preserves_nonempty_labels_and_nondefault_source_algorithm_shapes() {
        for source in [
            AlgorithmIdentifier::with_parameters(
                Pkcs1Algorithm::P_SPECIFIED.oid(),
                Asn1OctetString::new(b"label"),
            ),
            AlgorithmIdentifier::new(Pkcs1Algorithm::P_SPECIFIED.oid()),
            AlgorithmIdentifier::with_null(Pkcs1Algorithm::P_SPECIFIED.oid()),
            AlgorithmIdentifier::with_parameters(
                "1.2.3.4".parse().unwrap(),
                Asn1OctetString::new(&[]),
            ),
        ] {
            let params = RsaesOaepParams::new(
                RsaesOaepParams::sha1(),
                RsaesOaepParams::mgf1_sha1(),
                source.clone(),
            );
            assert_eq!(params.p_source_algorithm(), &source);
            let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(wire[2], 0xa2);
            assert_eq!(
                RsaesOaepParams::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                params
            );
        }
    }
}
