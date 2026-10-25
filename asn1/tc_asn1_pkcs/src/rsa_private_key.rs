//! RFC 8017 A.1.2 two-prime and multi-prime RSA private keys.
//!
//! ```text
//! RSAPrivateKey ::= SEQUENCE {
//!     version         INTEGER { two-prime(0), multi(1) },
//!     modulus         INTEGER,
//!     publicExponent  INTEGER,
//!     privateExponent INTEGER,
//!     prime1          INTEGER,
//!     prime2          INTEGER,
//!     exponent1       INTEGER,
//!     exponent2       INTEGER,
//!     coefficient     INTEGER,
//!     otherPrimeInfos OtherPrimeInfos OPTIONAL }
//! OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
//! OtherPrimeInfo ::= SEQUENCE {
//!     prime INTEGER, exponent INTEGER, coefficient INTEGER }
//! ```

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::RsaPublicKey;

/// One additional prime and its CRT exponent and coefficient.
///
/// This type does not verify that the values form a key. All three integers
/// are wiped when the value is dropped, including when decoding or `new` fails
/// after reading them. Debug redaction is a convenience, not a security
/// boundary. Equality and hashing are not constant time.
///
/// ```
/// use tc_asn1_pkcs::OtherPrimeInfo;
///
/// let prime = OtherPrimeInfo::new(23.into(), 7.into(), 2.into())?;
/// assert_eq!(prime.prime(), &23.into());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct OtherPrimeInfo {
    prime: Asn1Integer,
    exponent: Asn1Integer,
    coefficient: Asn1Integer,
}

impl OtherPrimeInfo {
    /// Rejects any zero or negative integer with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        prime: Asn1Integer,
        exponent: Asn1Integer,
        coefficient: Asn1Integer,
    ) -> Result<Self, Asn1Error> {
        // Built before checking, so a rejected value is still dropped and wiped.
        let value = Self {
            prime,
            exponent,
            coefficient,
        };
        value.check()?;
        Ok(value)
    }

    /// Rejects any zero or negative integer.
    fn check(&self) -> Result<(), Asn1Error> {
        if [&self.prime, &self.exponent, &self.coefficient]
            .into_iter()
            .any(not_positive)
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(())
    }

    /// Returns the prime.
    /// Variable time: branches only on the encoding structure.
    pub fn prime(&self) -> &Asn1Integer {
        &self.prime
    }

    /// Returns the exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn exponent(&self) -> &Asn1Integer {
        &self.exponent
    }

    /// Returns the coefficient.
    /// Variable time: branches only on the encoding structure.
    pub fn coefficient(&self) -> &Asn1Integer {
        &self.coefficient
    }
}

impl Zeroize for OtherPrimeInfo {
    /// Wipes all three integers, leaving zero.
    /// Constant time with respect to the values: the work depends only on the capacities.
    fn zeroize(&mut self) {
        self.prime.zeroize();
        self.exponent.zeroize();
        self.coefficient.zeroize();
    }
}

impl Drop for OtherPrimeInfo {
    /// Constant time with respect to the values: the work depends only on the capacities.
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OtherPrimeInfo {}

impl fmt::Debug for OtherPrimeInfo {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "OtherPrimeInfo { prime: <redacted>, exponent: <redacted>, coefficient: <redacted> }",
        )
    }
}

impl DecodeInner for OtherPrimeInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        // Each integer goes straight into the container, so an error after
        // reading one drops and wipes it.
        let mut value = Self {
            prime: fields.get()?,
            exponent: Asn1Integer::from(0),
            coefficient: Asn1Integer::from(0),
        };
        value.exponent = fields.get()?;
        value.coefficient = fields.get()?;
        fields.end()?;
        value.check()?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for OtherPrimeInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.prime.encoded_len(rules)
            + self.exponent.encoded_len(rules)
            + self.coefficient.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        at += self.prime.encode(rules, &mut out[at..])?;
        at += self.exponent.encode(rules, &mut out[at..])?;
        at += self.coefficient.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OtherPrimeInfo {}

impl Tagged for OtherPrimeInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherPrimeInfo {}

impl Encode for OtherPrimeInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

/// An RSA private key with a derived two-prime or multi-prime version.
///
/// This type does not verify that the values form a key. The private exponent,
/// the primes, the CRT exponents, the coefficient and any additional primes are
/// wiped when the value is dropped, including when decoding or `new` fails after
/// reading them; the modulus and public exponent are public. Other copies are
/// the caller's to protect: the input and encoded output buffers, and clones
/// until they are dropped. Debug redaction is a convenience, not a security
/// boundary. Equality and hashing are not constant time.
///
/// ```
/// use tc_asn1_pkcs::RsaPrivateKey;
///
/// let key = RsaPrivateKey::new(
///     323.into(), 5.into(), 173.into(), 17.into(), 19.into(),
///     13.into(), 11.into(), 9.into(),
/// )?;
/// assert_eq!(key.version(), 0);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct RsaPrivateKey {
    modulus: Asn1Integer,
    public_exponent: Asn1Integer,
    private_exponent: Asn1Integer,
    prime1: Asn1Integer,
    prime2: Asn1Integer,
    exponent1: Asn1Integer,
    exponent2: Asn1Integer,
    coefficient: Asn1Integer,
    other_prime_infos: Asn1SequenceOf<OtherPrimeInfo>,
}

impl RsaPrivateKey {
    /// Rejects any zero or negative integer with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    #[allow(clippy::too_many_arguments)] // The eight mandatory RSA components are distinct fields.
    pub fn new(
        modulus: Asn1Integer,
        public_exponent: Asn1Integer,
        private_exponent: Asn1Integer,
        prime1: Asn1Integer,
        prime2: Asn1Integer,
        exponent1: Asn1Integer,
        exponent2: Asn1Integer,
        coefficient: Asn1Integer,
    ) -> Result<Self, Asn1Error> {
        // Built before checking, so a rejected key is still dropped and wiped.
        let value = Self {
            modulus,
            public_exponent,
            private_exponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
            other_prime_infos: Asn1SequenceOf::new(Vec::new()),
        };
        value.check()?;
        Ok(value)
    }

    /// Rejects any zero or negative integer among the eight mandatory fields.
    fn check(&self) -> Result<(), Asn1Error> {
        if [
            &self.modulus,
            &self.public_exponent,
            &self.private_exponent,
            &self.prime1,
            &self.prime2,
            &self.exponent1,
            &self.exponent2,
            &self.coefficient,
        ]
        .into_iter()
        .any(not_positive)
        {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(())
    }

    /// Returns the modulus.
    /// Variable time: branches only on the encoding structure.
    pub fn modulus(&self) -> &Asn1Integer {
        &self.modulus
    }

    /// Returns the public exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn public_exponent(&self) -> &Asn1Integer {
        &self.public_exponent
    }

    /// Returns the private exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn private_exponent(&self) -> &Asn1Integer {
        &self.private_exponent
    }

    /// Returns the prime1.
    /// Variable time: branches only on the encoding structure.
    pub fn prime1(&self) -> &Asn1Integer {
        &self.prime1
    }

    /// Returns the prime2.
    /// Variable time: branches only on the encoding structure.
    pub fn prime2(&self) -> &Asn1Integer {
        &self.prime2
    }

    /// Returns the exponent1.
    /// Variable time: branches only on the encoding structure.
    pub fn exponent1(&self) -> &Asn1Integer {
        &self.exponent1
    }

    /// Returns the exponent2.
    /// Variable time: branches only on the encoding structure.
    pub fn exponent2(&self) -> &Asn1Integer {
        &self.exponent2
    }

    /// Returns the coefficient.
    /// Variable time: branches only on the encoding structure.
    pub fn coefficient(&self) -> &Asn1Integer {
        &self.coefficient
    }

    /// Adds additional primes; an empty list is `MalformedValue`.
    /// Omit the field by not calling this builder, not by passing an empty list.
    /// Variable time: branches only on the encoding structure.
    pub fn with_other_prime_infos(mut self, infos: Vec<OtherPrimeInfo>) -> Result<Self, Asn1Error> {
        if infos.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        self.other_prime_infos = Asn1SequenceOf::new(infos);
        Ok(self)
    }

    /// Returns zero for two primes or one when additional primes are present.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> u8 {
        u8::from(!self.other_prime_infos.elements().is_empty())
    }

    /// Returns the additional primes, or an empty slice when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn other_prime_infos(&self) -> &[OtherPrimeInfo] {
        self.other_prime_infos.elements()
    }

    /// Copies only the public modulus and exponent.
    /// Variable time: branches only on the encoding structure.
    pub fn to_public_key(&self) -> RsaPublicKey {
        RsaPublicKey::new(self.modulus.clone(), self.public_exponent.clone())
            .expect("private key construction validates the public integers")
    }
}

impl Zeroize for RsaPrivateKey {
    /// Wipes every secret field, leaving zero and no additional primes; the
    /// modulus and public exponent are public.
    /// Constant time with respect to the values: the work depends only on the capacities.
    fn zeroize(&mut self) {
        self.private_exponent.zeroize();
        self.prime1.zeroize();
        self.prime2.zeroize();
        self.exponent1.zeroize();
        self.exponent2.zeroize();
        self.coefficient.zeroize();
        self.other_prime_infos.zeroize();
    }
}

impl Drop for RsaPrivateKey {
    /// Constant time with respect to the values: the work depends only on the capacities.
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RsaPrivateKey {}

impl fmt::Debug for RsaPrivateKey {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RsaPrivateKey {{ modulus: {}, public_exponent: {}, ",
            self.modulus, self.public_exponent
        )?;
        f.write_str(concat!(
            "private_exponent: <redacted>, prime1: <redacted>, prime2: <redacted>, ",
            "exponent1: <redacted>, exponent2: <redacted>, coefficient: <redacted>, ",
            "other_prime_infos: <redacted> }",
        ))
    }
}

impl DecodeInner for RsaPrivateKey {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let version: Asn1Integer = fields.get()?;
        // The secret fields go straight into the container, so an error after
        // reading one drops and wipes it.
        let mut value = Self {
            modulus: fields.get()?,
            public_exponent: fields.get()?,
            private_exponent: Asn1Integer::from(0),
            prime1: Asn1Integer::from(0),
            prime2: Asn1Integer::from(0),
            exponent1: Asn1Integer::from(0),
            exponent2: Asn1Integer::from(0),
            coefficient: Asn1Integer::from(0),
            other_prime_infos: Asn1SequenceOf::new(Vec::new()),
        };
        value.private_exponent = fields.get()?;
        value.prime1 = fields.get()?;
        value.prime2 = fields.get()?;
        value.exponent1 = fields.get()?;
        value.exponent2 = fields.get()?;
        value.coefficient = fields.get()?;
        let infos = fields.get_opt::<Asn1SequenceOf<OtherPrimeInfo>>()?;
        fields.end()?;
        value.check()?;
        if let Some(infos) = infos {
            value = value.with_other_prime_infos(infos.into_elements())?;
        }
        if version.as_bytes() != [value.version()] {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for RsaPrivateKey {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        3 + self.modulus.encoded_len(rules)
            + self.public_exponent.encoded_len(rules)
            + self.private_exponent.encoded_len(rules)
            + self.prime1.encoded_len(rules)
            + self.prime2.encoded_len(rules)
            + self.exponent1.encoded_len(rules)
            + self.exponent2.encoded_len(rules)
            + self.coefficient.encoded_len(rules)
            + if self.other_prime_infos.elements().is_empty() {
                0
            } else {
                self.other_prime_infos.encoded_len(rules)
            }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out.get_mut(..3)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&[2, 1, self.version()]);
        let mut at = 3;
        at += self.modulus.encode(rules, &mut out[at..])?;
        at += self.public_exponent.encode(rules, &mut out[at..])?;
        at += self.private_exponent.encode(rules, &mut out[at..])?;
        at += self.prime1.encode(rules, &mut out[at..])?;
        at += self.prime2.encode(rules, &mut out[at..])?;
        at += self.exponent1.encode(rules, &mut out[at..])?;
        at += self.exponent2.encode(rules, &mut out[at..])?;
        at += self.coefficient.encode(rules, &mut out[at..])?;
        if !self.other_prime_infos.elements().is_empty() {
            at += self.other_prime_infos.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RsaPrivateKey {}

impl Tagged for RsaPrivateKey {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RsaPrivateKey {}

impl Encode for RsaPrivateKey {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

/// Zero and negative values are not valid RSA components.
fn not_positive(value: &Asn1Integer) -> bool {
    value.is_negative() || value.as_bytes() == [0]
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec, vec::Vec};

    use tc_asn1::{
        Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodeContent, EncodingOptions,
    };

    use super::{OtherPrimeInfo, RsaPrivateKey};

    const TWO_PRIME: &[u8] = &[
        0x30, 0x1d, 2, 1, 0, 2, 2, 1, 0x43, 2, 1, 5, 2, 2, 0, 0xad, 2, 1, 0x11, 2, 1, 0x13, 2, 1,
        0x0d, 2, 1, 0x0b, 2, 1, 9,
    ];

    fn sample() -> RsaPrivateKey {
        RsaPrivateKey::new(
            323.into(),
            5.into(),
            173.into(),
            17.into(),
            19.into(),
            13.into(),
            11.into(),
            9.into(),
        )
        .unwrap()
    }

    #[test]
    fn the_two_prime_vector_preserves_sign_octets_and_projects_the_public_key() {
        let key = sample();
        assert_eq!(key.encode_to_vec(&EncodingOptions::DER).unwrap(), TWO_PRIME);
        assert_eq!(
            RsaPrivateKey::decode(TWO_PRIME, &DecodingOptions::default()).unwrap(),
            (TWO_PRIME.len(), key.clone())
        );
        assert_eq!(
            RsaPrivateKey::decode_der(TWO_PRIME, &DecodingOptions::default())
                .unwrap()
                .1,
            key
        );
        assert_eq!(key.version(), 0);
        assert!(key.other_prime_infos().is_empty());
        assert_eq!(
            key.to_public_key()
                .encode_to_vec(&EncodingOptions::DER)
                .unwrap(),
            b"\x30\x07\x02\x02\x01\x43\x02\x01\x05",
        );
        assert_eq!(
            [
                key.modulus(),
                key.public_exponent(),
                key.private_exponent(),
                key.prime1(),
                key.prime2(),
                key.exponent1(),
                key.exponent2(),
                key.coefficient()
            ],
            [
                &323.into(),
                &5.into(),
                &173.into(),
                &17.into(),
                &19.into(),
                &13.into(),
                &11.into(),
                &9.into()
            ],
        );
    }

    #[test]
    fn adding_an_extra_prime_derives_version_one_and_round_trips_under_all_rules() {
        let info = OtherPrimeInfo::new(23.into(), 7.into(), 2.into()).unwrap();
        assert_eq!(
            [info.prime(), info.exponent(), info.coefficient()],
            [&23.into(), &7.into(), &2.into()]
        );
        let key = sample().with_other_prime_infos(vec![info]).unwrap();
        assert_eq!(key.version(), 1);
        for rules in [
            EncodingOptions::BER,
            EncodingOptions::CER,
            EncodingOptions::DER,
        ] {
            let wire = key.encode_to_vec(&rules).unwrap();
            assert_eq!(wire.len(), key.encoded_len(&rules));
            assert_eq!(
                RsaPrivateKey::decode(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                key
            );
        }
        let wire = key.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire[4], 1);
        assert_eq!(
            RsaPrivateKey::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            key
        );
    }

    #[test]
    fn private_key_versions_must_agree_with_a_nonempty_additional_prime_list() {
        for version in [1, 2, 255] {
            let mut wire = TWO_PRIME.to_vec();
            wire[4] = version;
            assert_eq!(
                RsaPrivateKey::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
        let key = sample()
            .with_other_prime_infos(vec![
                OtherPrimeInfo::new(1.into(), 1.into(), 1.into()).unwrap(),
            ])
            .unwrap();
        let mut wire = key.encode_to_vec(&EncodingOptions::DER).unwrap();
        wire[4] = 0;
        assert_eq!(
            RsaPrivateKey::decode_der(&wire, &DecodingOptions::default()),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            sample().with_other_prime_infos(Vec::new()),
            Err(Asn1Error::MalformedValue)
        );
        for version in [0, 1] {
            let mut wire = TWO_PRIME.to_vec();
            wire[1] += 2;
            wire[4] = version;
            wire.extend_from_slice(&[0x30, 0]);
            assert_eq!(
                RsaPrivateKey::decode_der(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn every_rsa_private_component_rejects_zero_and_negative_integers() {
        for index in 0..8 {
            for bad in [0, -1] {
                let mut values = [1; 8];
                values[index] = bad;
                let [n, e, d, p, q, dp, dq, qi] = values.map(Asn1Integer::from);
                assert_eq!(
                    RsaPrivateKey::new(n, e, d, p, q, dp, dq, qi),
                    Err(Asn1Error::MalformedValue)
                );
                let mut wire = vec![0x30, 27, 2, 1, 0];
                for value in values {
                    wire.extend_from_slice(&[2, 1, value as u8]);
                }
                assert_eq!(
                    RsaPrivateKey::decode_der(&wire, &DecodingOptions::default()),
                    Err(Asn1Error::MalformedValue)
                );
            }
        }
        for index in 0..3 {
            for bad in [0, -1] {
                let mut values = [1; 3];
                values[index] = bad;
                let [p, e, c] = values.map(Asn1Integer::from);
                assert_eq!(OtherPrimeInfo::new(p, e, c), Err(Asn1Error::MalformedValue));
                let mut wire = vec![0x30, 9];
                for value in values {
                    wire.extend_from_slice(&[2, 1, value as u8]);
                }
                assert_eq!(
                    OtherPrimeInfo::decode_der(&wire, &DecodingOptions::default()),
                    Err(Asn1Error::MalformedValue)
                );
            }
        }
    }

    #[test]
    fn zeroizing_clears_every_secret_component_and_keeps_the_public_key() {
        use tc_zeroize::Zeroize;
        let mut key = sample()
            .with_other_prime_infos(vec![
                OtherPrimeInfo::new(23.into(), 3.into(), 5.into()).unwrap(),
            ])
            .unwrap();
        key.zeroize();
        let zero = Asn1Integer::from(0);
        for secret in [
            key.private_exponent(),
            key.prime1(),
            key.prime2(),
            key.exponent1(),
            key.exponent2(),
            key.coefficient(),
        ] {
            assert_eq!(secret, &zero);
        }
        assert!(key.other_prime_infos().is_empty());
        assert_eq!(key.modulus(), &Asn1Integer::from(323));
        assert_eq!(key.public_exponent(), &Asn1Integer::from(5));

        let mut prime = OtherPrimeInfo::new(23.into(), 3.into(), 5.into()).unwrap();
        prime.zeroize();
        assert_eq!(
            [prime.prime(), prime.exponent(), prime.coefficient()],
            [&zero, &zero, &zero]
        );
    }

    #[test]
    fn private_key_debug_shows_public_components_but_redacts_all_secrets() {
        let debug = format!("{:?}", sample());
        assert!(debug.contains("modulus: 323"));
        assert!(debug.contains("public_exponent: 5"));
        assert!(!debug.contains("173"));
        for field in [
            "private_exponent",
            "prime1",
            "prime2",
            "exponent1",
            "exponent2",
            "coefficient",
            "other_prime_infos",
        ] {
            assert!(debug.contains(&format!("{field}: <redacted>")));
        }
        let info = OtherPrimeInfo::new(23.into(), 7.into(), 2.into()).unwrap();
        assert_eq!(
            format!("{info:?}"),
            "OtherPrimeInfo { prime: <redacted>, exponent: <redacted>, coefficient: <redacted> }"
        );
    }

    #[test]
    fn private_key_and_extra_prime_sequences_reject_missing_extra_and_wrongly_tagged_fields() {
        let mut missing = TWO_PRIME[..TWO_PRIME.len() - 3].to_vec();
        missing[1] -= 3;
        let mut extra = TWO_PRIME.to_vec();
        extra[1] += 2;
        extra.extend_from_slice(&[5, 0]);
        let mut wrong = TWO_PRIME.to_vec();
        wrong[0] = 0x31;
        for (wire, error) in [
            (missing, Asn1Error::Truncated),
            (extra, Asn1Error::TrailingData),
            (wrong, Asn1Error::UnexpectedTag),
        ] {
            assert_eq!(
                RsaPrivateKey::decode_der(&wire, &DecodingOptions::default()),
                Err(error)
            );
        }
        for (wire, error) in [
            (
                &b"\x30\x06\x02\x01\x01\x02\x01\x01"[..],
                Asn1Error::Truncated,
            ),
            (
                &b"\x30\x0b\x02\x01\x01\x02\x01\x01\x02\x01\x01\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
            (&b"\x31\x00"[..], Asn1Error::UnexpectedTag),
            (&b"\x30\x02\x05\x00"[..], Asn1Error::UnexpectedTag),
        ] {
            assert_eq!(
                OtherPrimeInfo::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
        assert_eq!(
            sample().encode_content(&EncodingOptions::DER, &mut [0; 2]),
            Err(Asn1Error::BufferTooSmall)
        );
    }
}
