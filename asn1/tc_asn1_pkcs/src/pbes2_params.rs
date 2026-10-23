//! RFC 8018 A.4 PBES2 parameters.
//!
//! ```text
//! PBES2-params ::= SEQUENCE {
//!     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
//!     encryptionScheme  AlgorithmIdentifier {{PBES2-Encs}} }
//! ```
//!
//! Both identifiers stay uninterpreted: the key derivation function is usually
//! PBKDF2 with [`Pbkdf2Params`](crate::Pbkdf2Params), the encryption scheme a
//! block cipher in CBC mode with its IV as parameters.

use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// A key derivation function and an encryption scheme.
///
/// ```
/// use tc_asn1::Asn1OctetString;
/// use tc_asn1_pkcs::{Pbes2Params, Pkcs5Algorithm};
/// use tc_asn1_x509::alg::AlgorithmIdentifier;
///
/// let params = Pbes2Params::new(
///     AlgorithmIdentifier::new(Pkcs5Algorithm::PBKDF2.oid()),
///     AlgorithmIdentifier::with_parameters(
///         "2.16.840.1.101.3.4.1.42".parse()?,
///         Asn1OctetString::new(&[0; 16]),
///     ),
/// );
/// assert_eq!(params.key_derivation_func().algorithm(), &Pkcs5Algorithm::PBKDF2.oid());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pbes2Params {
    key_derivation_func: AlgorithmIdentifier,
    encryption_scheme: AlgorithmIdentifier,
}

impl Pbes2Params {
    /// Stores both identifiers without interpreting either.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        key_derivation_func: AlgorithmIdentifier,
        encryption_scheme: AlgorithmIdentifier,
    ) -> Self {
        Self {
            key_derivation_func,
            encryption_scheme,
        }
    }

    /// Returns the key derivation function and its parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn key_derivation_func(&self) -> &AlgorithmIdentifier {
        &self.key_derivation_func
    }

    /// Returns the encryption scheme and its parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_scheme(&self) -> &AlgorithmIdentifier {
        &self.encryption_scheme
    }
}

impl fmt::Display for Pbes2Params {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KDF {}, encryption {}",
            self.key_derivation_func.algorithm(),
            self.encryption_scheme.algorithm()
        )
    }
}

impl DecodeInner for Pbes2Params {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let mut fields = element.children(context)?;
        let key_derivation_func = fields.get()?;
        let encryption_scheme = fields.get()?;
        fields.end()?;
        Ok((
            element.total_len(),
            Self::new(key_derivation_func, encryption_scheme),
        ))
    }
}

impl EncodeContent for Pbes2Params {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_derivation_func.encoded_len(rules) + self.encryption_scheme.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        at += self.key_derivation_func.encode(rules, &mut out[at..])?;
        at += self.encryption_scheme.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Pbes2Params {}

impl Tagged for Pbes2Params {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Pbes2Params {}

impl Encode for Pbes2Params {
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

    use tc_asn1::{Asn1Error, Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::Pbes2Params;
    use crate::{Pbkdf2Params, Pkcs5Algorithm};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 2048`.
    const OPENSSL: &str = concat!(
        "3052303106092a864886f70d01050c302404109720f2fe1c4e34713399cdc892ef838602020800300c06082a",
        "864886f70d02090500301d060960864801650304012a04101cbaa2e315e193a0fd4d80dfaf1a5829",
    );

    #[test]
    fn openssl_pbes2_parameters_decode_to_pbkdf2_and_aes_cbc() {
        let wire = hex(OPENSSL);
        let params = Pbes2Params::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(params.encode_to_vec(&EncodingOptions::DER).unwrap(), wire);
        assert_eq!(
            params.key_derivation_func().algorithm(),
            &Pkcs5Algorithm::PBKDF2.oid()
        );
        let kdf = params
            .key_derivation_func()
            .parameters()
            .unwrap()
            .encode_to_vec(&EncodingOptions::DER)
            .unwrap();
        let kdf = Pbkdf2Params::decode_der(&kdf, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(kdf.iteration_count().as_bytes(), [0x08, 0x00]);
        assert!(matches!(
            params.encryption_scheme().parameters(),
            Some(Asn1Object::OctetString(iv)) if iv.as_bytes() == hex("1cbaa2e315e193a0fd4d80dfaf1a5829")
        ));
        assert_eq!(
            params.to_string(),
            "KDF 1.2.840.113549.1.5.12, encryption 2.16.840.1.101.3.4.1.42"
        );
    }

    #[test]
    fn pbes2_parameters_need_both_identifiers_and_nothing_more() {
        for (wire, error) in [
            (&[0x30, 0][..], Asn1Error::Truncated),
            (&[0x30, 4, 0x30, 2, 6, 0][..], Asn1Error::MalformedValue),
            (&[0x30, 2, 4, 0][..], Asn1Error::UnexpectedTag),
        ] {
            assert_eq!(
                Pbes2Params::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
