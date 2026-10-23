//! RFC 8018 A.2 PBKDF2 parameters.
//!
//! ```text
//! PBKDF2-params ::= SEQUENCE {
//!     salt CHOICE {
//!         specified OCTET STRING,
//!         otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}} },
//!     iterationCount INTEGER (1..MAX),
//!     keyLength      INTEGER (1..MAX) OPTIONAL,
//!     prf            AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1 }
//! ```
//!
//! Only the specified salt is supported: RFC 8018 reserves `otherSource` for
//! future versions. The default PRF includes its NULL parameters; a written
//! default is accepted under BER and rejected under DER, and encoding omits it.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::Pkcs5Algorithm;

/// A salt, an iteration count, an optional key length and a PRF.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Encode, EncodingOptions};
/// use tc_asn1_pkcs::{Pbkdf2Params, Pkcs5Algorithm};
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let params = Pbkdf2Params::new(Asn1OctetString::new(&[1; 16]), 2048.into())?
///     .with_prf(AlgorithmIdentifier::with_null(Pkcs5Algorithm::HMAC_WITH_SHA256.oid()));
/// assert_eq!(params.prf().algorithm(), &Pkcs5Algorithm::HMAC_WITH_SHA256.oid());
/// assert!(params.key_length().is_none());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pbkdf2Params {
    salt: Asn1OctetString,
    iteration_count: Asn1Integer,
    key_length: Option<Asn1Integer>,
    prf: AlgorithmIdentifier,
}

impl Pbkdf2Params {
    /// The PRF is the default HMAC-SHA1 and the key length absent. Rejects an
    /// iteration count below one with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(salt: Asn1OctetString, iteration_count: Asn1Integer) -> Result<Self, Asn1Error> {
        if !is_positive(&iteration_count) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            salt,
            iteration_count,
            key_length: None,
            prf: Self::hmac_with_sha1(),
        })
    }

    /// The default PRF, HMAC-SHA1 with NULL parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn hmac_with_sha1() -> AlgorithmIdentifier {
        AlgorithmIdentifier::with_null(Pkcs5Algorithm::HMAC_WITH_SHA1.oid())
    }

    /// Sets the key length in octets. Rejects a length below one with
    /// `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_key_length(mut self, key_length: Asn1Integer) -> Result<Self, Asn1Error> {
        if !is_positive(&key_length) {
            return Err(Asn1Error::MalformedValue);
        }
        self.key_length = Some(key_length);
        Ok(self)
    }

    /// Sets the PRF without checking it.
    /// Variable time: branches only on the encoding structure.
    pub fn with_prf(mut self, prf: AlgorithmIdentifier) -> Self {
        self.prf = prf;
        self
    }

    /// Returns the salt.
    /// Variable time: branches only on the encoding structure.
    pub fn salt(&self) -> &Asn1OctetString {
        &self.salt
    }

    /// Returns the iteration count.
    /// Variable time: branches only on the encoding structure.
    pub fn iteration_count(&self) -> &Asn1Integer {
        &self.iteration_count
    }

    /// Returns the key length in octets, if written.
    /// Variable time: branches only on the encoding structure.
    pub fn key_length(&self) -> Option<&Asn1Integer> {
        self.key_length.as_ref()
    }

    /// Returns the PRF, the default when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn prf(&self) -> &AlgorithmIdentifier {
        &self.prf
    }

    fn writes_prf(&self) -> bool {
        self.prf != Self::hmac_with_sha1()
    }
}

fn is_positive(value: &Asn1Integer) -> bool {
    !value.is_negative() && value.as_bytes() != [0]
}

impl fmt::Display for Pbkdf2Params {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} salt octets, iteration count {}",
            self.salt.as_bytes().len(),
            self.iteration_count
        )?;
        if let Some(key_length) = &self.key_length {
            write!(f, ", key length {key_length}")?;
        }
        write!(f, ", PRF {}", self.prf.algorithm())
    }
}

impl DecodeInner for Pbkdf2Params {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let salt = fields.get()?;
        let iteration_count = fields.get()?;
        let key_length = fields.get_opt()?;
        let prf = fields.get_default(Self::hmac_with_sha1())?;
        fields.end()?;
        let params = Self::new(salt, iteration_count)?.with_prf(prf);
        let params = match key_length {
            Some(key_length) => params.with_key_length(key_length)?,
            None => params,
        };
        Ok((element.total_len(), params))
    }
}

impl EncodeContent for Pbkdf2Params {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = self.salt.encoded_len(rules) + self.iteration_count.encoded_len(rules);
        if let Some(key_length) = &self.key_length {
            len += key_length.encoded_len(rules);
        }
        if self.writes_prf() {
            len += self.prf.encoded_len(rules);
        }
        len
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        at += self.salt.encode(rules, &mut out[at..])?;
        at += self.iteration_count.encode(rules, &mut out[at..])?;
        if let Some(key_length) = &self.key_length {
            at += key_length.encode(rules, &mut out[at..])?;
        }
        if self.writes_prf() {
            at += self.prf.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Pbkdf2Params {}

impl Tagged for Pbkdf2Params {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Pbkdf2Params {}

impl Encode for Pbkdf2Params {
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
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{Asn1Error, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
    use tc_asn1_x509::alg::AlgorithmIdentifier;

    use super::Pbkdf2Params;
    use crate::Pkcs5Algorithm;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 2048`.
    const OPENSSL_SHA256: &str =
        "302404109720f2fe1c4e34713399cdc892ef838602020800300c06082a864886f70d02090500";
    /// `openssl pkcs8 -topk8 -v2 aes-128-cbc -v2prf hmacWithSHA1 -iter 1000`: the default PRF
    /// is left out.
    const OPENSSL_SHA1: &str = "30160410be231e4a99c2760d2e46e0a5c906e2a6020203e8";

    #[test]
    fn openssl_pbkdf2_parameters_decode_and_encode_back() {
        let wire = hex(OPENSSL_SHA256);
        let params = Pbkdf2Params::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(
            params.salt().as_bytes(),
            hex("9720f2fe1c4e34713399cdc892ef8386")
        );
        assert_eq!(params.iteration_count().as_bytes(), [0x08, 0x00]);
        assert!(params.key_length().is_none());
        assert_eq!(
            params.prf(),
            &AlgorithmIdentifier::with_null(Pkcs5Algorithm::HMAC_WITH_SHA256.oid())
        );
        assert_eq!(params.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);

        let wire = hex(OPENSSL_SHA1);
        let params = Pbkdf2Params::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(params.prf(), &Pbkdf2Params::hmac_with_sha1());
        assert_eq!(params.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            params.to_string(),
            "16 salt octets, iteration count 1000, PRF 1.2.840.113549.2.7"
        );
    }

    #[test]
    fn a_written_default_prf_is_ber_only_and_the_key_length_round_trips() {
        let mut ber = hex(OPENSSL_SHA1);
        ber[1] += 14;
        ber.extend(hex("300c06082a864886f70d02070500"));
        let params = Pbkdf2Params::decode(&ber, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(params.prf(), &Pbkdf2Params::hmac_with_sha1());
        assert_eq!(
            Pbkdf2Params::decode_der(&ber, &DecodingOptions::default()),
            Err(Asn1Error::NotDer)
        );

        let params = Pbkdf2Params::new(Asn1OctetString::new(&[1; 8]), 1.into())
            .unwrap()
            .with_key_length(32.into())
            .unwrap();
        let wire = params.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire, hex("301004080101010101010101020101020120"));
        assert_eq!(
            Pbkdf2Params::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            params
        );
    }

    #[test]
    fn counts_and_key_lengths_below_one_and_other_salt_sources_are_refused() {
        let salt = || Asn1OctetString::new(&[1; 8]);
        for count in [0, -1] {
            assert_eq!(
                Pbkdf2Params::new(salt(), count.into()),
                Err(Asn1Error::MalformedValue)
            );
            assert_eq!(
                Pbkdf2Params::new(salt(), 1.into())
                    .unwrap()
                    .with_key_length(count.into()),
                Err(Asn1Error::MalformedValue)
            );
        }
        let other_source = hex("300a300506032a0304020101");
        assert!(Pbkdf2Params::decode_der(&other_source, &DecodingOptions::default()).is_err());
    }
}
