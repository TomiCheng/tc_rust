//! RFC 8017 A.2.3 RSASSA-PSS parameters.
//!
//! ```text
//! RSASSA-PSS-params ::= SEQUENCE {
//!     hashAlgorithm    [0] HashAlgorithm    DEFAULT sha1,
//!     maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
//!     saltLength       [2] INTEGER          DEFAULT 20,
//!     trailerField     [3] INTEGER          DEFAULT 1 }
//! ```
//!
//! All context tags are EXPLICIT. Defaults include the SHA-1 identifier's NULL
//! parameters; absent parameters are a distinct value. Written defaults are
//! accepted under BER and rejected under DER. Encoding omits exact defaults.
//! Algorithm suitability is left to the caller.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::AlgorithmIdentifier;

use crate::rsa_defaults;

/// PSS hash, mask, salt length and trailer parameters.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_pkcs::RsassaPssParams;
///
/// let params = RsassaPssParams::default_params();
/// assert_eq!(params.encode_to_vec(&EncodingOptions::DER)?, [0x30, 0]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RsassaPssParams {
    hash_algorithm: AlgorithmIdentifier,
    mask_gen_algorithm: AlgorithmIdentifier,
    salt_length: Asn1Integer,
    trailer_field: Asn1Integer,
}

impl RsassaPssParams {
    /// Rejects a negative salt length or a trailer field other than one.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        hash_algorithm: AlgorithmIdentifier,
        mask_gen_algorithm: AlgorithmIdentifier,
        salt_length: Asn1Integer,
        trailer_field: Asn1Integer,
    ) -> Result<Self, Asn1Error> {
        if salt_length.is_negative() || trailer_field.as_bytes() != [1] {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            hash_algorithm,
            mask_gen_algorithm,
            salt_length,
            trailer_field,
        })
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

    /// Returns the exact RFC 8017 defaults.
    /// Variable time: branches only on the encoding structure.
    pub fn default_params() -> Self {
        Self {
            hash_algorithm: Self::sha1(),
            mask_gen_algorithm: Self::mgf1_sha1(),
            salt_length: 20.into(),
            trailer_field: 1.into(),
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

    /// Returns the salt length.
    /// Variable time: branches only on the encoding structure.
    pub fn salt_length(&self) -> &Asn1Integer {
        &self.salt_length
    }

    /// Returns the trailer field.
    /// Variable time: branches only on the encoding structure.
    pub fn trailer_field(&self) -> &Asn1Integer {
        &self.trailer_field
    }
}

impl Default for RsassaPssParams {
    /// Variable time: branches only on the encoding structure.
    fn default() -> Self {
        Self::default_params()
    }
}

impl fmt::Display for RsassaPssParams {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hash algorithm: {}, mask gen algorithm: {}, salt length: {}, trailer field: {}",
            self.hash_algorithm, self.mask_gen_algorithm, self.salt_length, self.trailer_field
        )
    }
}

impl DecodeInner for RsassaPssParams {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let hash_algorithm = fields.get_explicit_default([0xa0], Self::sha1())?;
        let mask_gen_algorithm = fields.get_explicit_default([0xa1], Self::mgf1_sha1())?;
        let salt_length = fields.get_explicit_default([0xa2], 20.into())?;
        let trailer_field = fields.get_explicit_default([0xa3], 1.into())?;
        fields.end()?;
        Ok((
            element.total_len(),
            Self::new(
                hash_algorithm,
                mask_gen_algorithm,
                salt_length,
                trailer_field,
            )?,
        ))
    }
}

impl EncodeContent for RsassaPssParams {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = 0;
        if !rsa_defaults::is_sha1(&self.hash_algorithm) {
            len += Explicit::new(&[0xa0], &self.hash_algorithm).encoded_len(rules);
        }
        if !rsa_defaults::is_mgf1_sha1(&self.mask_gen_algorithm) {
            len += Explicit::new(&[0xa1], &self.mask_gen_algorithm).encoded_len(rules);
        }
        if self.salt_length.as_bytes() != [20] {
            len += Explicit::new(&[0xa2], &self.salt_length).encoded_len(rules);
        }
        if self.trailer_field.as_bytes() != [1] {
            len += Explicit::new(&[0xa3], &self.trailer_field).encoded_len(rules);
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
        if self.salt_length.as_bytes() != [20] {
            at += Explicit::new(&[0xa2], &self.salt_length).encode(rules, &mut out[at..])?;
        }
        if self.trailer_field.as_bytes() != [1] {
            at += Explicit::new(&[0xa3], &self.trailer_field).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RsassaPssParams {}

impl Tagged for RsassaPssParams {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RsassaPssParams {}

impl Encode for RsassaPssParams {
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
        Asn1Error, Asn1Integer, Asn1Null, Asn1Object, Decode, DecodingOptions, Encode,
        EncodeContent, EncodingOptions, Explicit,
    };
    use tc_asn1_x509::AlgorithmIdentifier;

    use crate::Pkcs1Algorithm;

    use super::RsassaPssParams;

    fn sequence(content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128);
        let mut wire = vec![0x30, content.len() as u8];
        wire.extend_from_slice(content);
        wire
    }

    #[test]
    fn pss_defaults_encode_as_an_empty_sequence_and_preserve_exact_parameters() {
        let params = RsassaPssParams::default_params();
        assert_eq!(params, RsassaPssParams::default());
        assert_eq!(params.hash_algorithm(), &RsassaPssParams::sha1());
        assert_eq!(params.mask_gen_algorithm(), &RsassaPssParams::mgf1_sha1());
        assert_eq!(params.salt_length(), &20.into());
        assert_eq!(params.trailer_field(), &1.into());
        assert_eq!(
            params.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0x30, 0]
        );
        assert_eq!(
            RsassaPssParams::decode_der(&[0x30, 0], &DecodingOptions::default())
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
            RsassaPssParams::sha1()
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            [0x30, 9, 6, 5, 0x2b, 0x0e, 3, 2, 0x1a, 5, 0],
        );
        assert_eq!(
            RsassaPssParams::mgf1_sha1()
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            [
                0x30, 0x16, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 8, 0x30, 9, 6, 5, 0x2b,
                0x0e, 3, 2, 0x1a, 5, 0
            ],
        );
    }

    #[test]
    fn every_explicit_pss_default_is_accepted_under_ber_and_rejected_under_der() {
        let defaults = RsassaPssParams::default_params();
        let mut together = Vec::new();
        for content in [
            Explicit::new(&[0xa0], defaults.hash_algorithm())
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            Explicit::new(&[0xa1], defaults.mask_gen_algorithm())
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            Explicit::new(&[0xa2], defaults.salt_length())
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            Explicit::new(&[0xa3], defaults.trailer_field())
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
        ] {
            let wire = sequence(&content);
            assert_eq!(
                RsassaPssParams::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                defaults
            );
            assert_eq!(
                RsassaPssParams::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::NotDer)
            );
            together.extend_from_slice(&content);
        }
        let wire = sequence(&together);
        assert_eq!(
            RsassaPssParams::decode(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            defaults
        );
        assert_eq!(
            RsassaPssParams::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );
    }

    #[test]
    fn nondefault_pss_hashes_are_explicitly_wrapped_and_round_trip_under_all_rules() {
        let hash = AlgorithmIdentifier::with_null(Pkcs1Algorithm::SHA256.oid());
        let params =
            RsassaPssParams::new(hash, RsassaPssParams::mgf1_sha1(), 20.into(), 1.into()).unwrap();
        let expected = [
            0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1, 5, 0,
        ];
        assert_eq!(
            params.encode_to_vec(&EncodingOptions::DER).unwrap(),
            expected
        );
        assert_eq!(
            RsassaPssParams::decode_der(&expected, &DecodingOptions::default())
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
                RsassaPssParams::decode(&wire, &DecodingOptions::default())
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
        let params = RsassaPssParams::new(hash, mask, 20.into(), 1.into()).unwrap();
        let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert!(wire.contains(&0xa0));
        assert!(wire.contains(&0xa1));
        assert_eq!(
            RsassaPssParams::decode_der(&wire, &DecodingOptions::default())
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
            let params =
                RsassaPssParams::new(RsassaPssParams::sha1(), mask, 20.into(), 1.into()).unwrap();
            let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(wire[2], 0xa1);
            assert_eq!(
                RsassaPssParams::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                params
            );
        }
    }

    #[test]
    fn pss_fields_require_explicit_wrappers_and_schema_order() {
        let implicit = [0x30, 0x0b, 0xa0, 9, 6, 5, 0x2b, 0x0e, 3, 2, 0x1a, 5, 0];
        assert_eq!(
            RsassaPssParams::decode_der(&implicit, &DecodingOptions::default()),
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
                RsassaPssParams::decode_der(&sequence(&content), &DecodingOptions::default()),
                Err(Asn1Error::TrailingData)
            );
        }
        for (wire, error) in [
            (&[0x31, 0][..], Asn1Error::UnexpectedTag),
            (&[0x30, 2, 0xa0, 0][..], Asn1Error::Truncated),
            (&[0x30, 2, 5, 0][..], Asn1Error::TrailingData),
        ] {
            assert_eq!(
                RsassaPssParams::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
        let mut content = a0;
        content[1] += 2;
        content.extend_from_slice(&[5, 0]);
        assert_eq!(
            RsassaPssParams::decode_der(&sequence(&content), &DecodingOptions::default()),
            Err(Asn1Error::TrailingData)
        );
    }

    #[test]
    fn pss_rejects_negative_salt_lengths_and_every_trailer_except_one() {
        assert_eq!(
            RsassaPssParams::new(
                RsassaPssParams::sha1(),
                RsassaPssParams::mgf1_sha1(),
                (-1).into(),
                1.into()
            ),
            Err(Asn1Error::MalformedValue),
        );
        for trailer in [-1, 0, 2, 256] {
            assert_eq!(
                RsassaPssParams::new(
                    RsassaPssParams::sha1(),
                    RsassaPssParams::mgf1_sha1(),
                    20.into(),
                    trailer.into()
                ),
                Err(Asn1Error::MalformedValue),
            );
            let content = Explicit::new(&[0xa3], &Asn1Integer::from(trailer))
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap();
            assert_eq!(
                RsassaPssParams::decode_der(&sequence(&content), &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        let wire = [0x30, 5, 0xa2, 3, 2, 1, 0xff];
        assert_eq!(
            RsassaPssParams::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn pss_accepts_zero_and_arbitrarily_large_nonnegative_salt_lengths() {
        for salt in [
            Asn1Integer::from(0),
            (1u64 << 32).into(),
            Asn1Integer::from_unsigned_bytes(&[0xff; 80]),
        ] {
            let params = RsassaPssParams::new(
                RsassaPssParams::sha1(),
                RsassaPssParams::mgf1_sha1(),
                salt.clone(),
                1.into(),
            )
            .unwrap();
            assert_eq!(params.salt_length(), &salt);
            let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(wire[2], 0xa2);
            assert_eq!(
                RsassaPssParams::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                params
            );
        }
    }
}
