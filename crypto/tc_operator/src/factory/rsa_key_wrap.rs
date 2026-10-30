use tc_asn1::{Asn1Object, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_pkcs::RsaesOaepParams;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::SecurityError;

use crate::OperatorError;

const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const ID_RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
const ID_MGF1: &str = "1.2.840.113549.1.1.8";
const SHA1: &str = "1.3.14.3.2.26";
const SHA224: &str = "2.16.840.1.101.3.4.2.4";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA384: &str = "2.16.840.1.101.3.4.2.2";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";

const PKCS1_CIPHER: &str = "RSA/NONE/PKCS1PADDING";

const NAMES: &[(&str, Option<(&str, &str)>)] = &[
    ("RSA/ECB/PKCS1PADDING", None),
    ("RSA/NONE/PKCS1PADDING", None),
    ("RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING", Some((SHA1, SHA1))),
    (
        "RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING",
        Some((SHA224, SHA224)),
    ),
    (
        "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING",
        Some((SHA256, SHA256)),
    ),
    (
        "RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING",
        Some((SHA384, SHA384)),
    ),
    (
        "RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING",
        Some((SHA512, SHA512)),
    ),
    (
        "RSA/NONE/OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
        Some((SHA256, SHA1)),
    ),
];

const OAEP_CIPHERS: &[(&str, &str, &str)] = &[
    (SHA1, SHA1, "RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING"),
    (SHA224, SHA224, "RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING"),
    (SHA256, SHA256, "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING"),
    (SHA384, SHA384, "RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING"),
    (SHA512, SHA512, "RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING"),
    (
        SHA256,
        SHA1,
        "RSA/NONE/OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
    ),
];

pub(super) struct RsaKeyWrap {
    pub(super) algorithm: AlgorithmIdentifier,
    pub(super) cipher: &'static str,
}

impl RsaKeyWrap {
    pub(super) fn by_name(name: &str) -> Result<Self, OperatorError> {
        let (_, oaep) = NAMES
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
            .ok_or(SecurityError::UnknownCipher)?;
        match oaep {
            None => Ok(Self::pkcs1()),
            Some((digest, mgf)) => Self::oaep(digest, mgf),
        }
    }

    pub(super) fn by_algorithm(algorithm: &AlgorithmIdentifier) -> Result<Self, OperatorError> {
        match algorithm.algorithm().to_string().as_str() {
            RSA_ENCRYPTION => Ok(Self::pkcs1()),
            ID_RSAES_OAEP => {
                let params: RsaesOaepParams = match algorithm.parameters() {
                    None => RsaesOaepParams::default_params(),
                    Some(parameters) => reparse(parameters)?,
                };
                let digest = params.hash_algorithm().algorithm().to_string();
                let mgf = params.mask_gen_algorithm();
                let mgf = if mgf.algorithm().to_string() == ID_MGF1 {
                    let inner: AlgorithmIdentifier =
                        reparse(mgf.parameters().ok_or(SecurityError::UnknownCipher)?)?;
                    inner.algorithm().to_string()
                } else {
                    mgf.algorithm().to_string()
                };
                Self::oaep(&digest, &mgf)
            }
            _ => Err(SecurityError::UnknownCipher.into()),
        }
    }

    fn pkcs1() -> Self {
        Self {
            algorithm: AlgorithmIdentifier::with_null(RSA_ENCRYPTION.parse().unwrap()),
            cipher: PKCS1_CIPHER,
        }
    }

    fn oaep(digest: &str, mgf: &str) -> Result<Self, OperatorError> {
        let (_, _, cipher) = OAEP_CIPHERS
            .iter()
            .find(|(d, m, _)| *d == digest && *m == mgf)
            .ok_or(SecurityError::UnknownCipher)?;
        let params = RsaesOaepParams::new(
            AlgorithmIdentifier::with_null(digest.parse()?),
            AlgorithmIdentifier::with_parameters(
                ID_MGF1.parse()?,
                to_object(&AlgorithmIdentifier::with_null(mgf.parse()?))?,
            ),
            RsaesOaepParams::p_specified_empty(),
        );
        Ok(Self {
            algorithm: AlgorithmIdentifier::with_parameters(
                ID_RSAES_OAEP.parse()?,
                to_object(&params)?,
            ),
            cipher,
        })
    }
}

fn reparse<T: Decode>(parameters: &Asn1Object) -> Result<T, OperatorError> {
    let der = parameters.encode_to_vec(&EncodingOptions::DER)?;
    Ok(T::decode(&der, &DecodingOptions::default())?.1)
}

fn to_object<T: Encode>(value: &T) -> Result<Asn1Object, OperatorError> {
    let der = value.encode_to_vec(&EncodingOptions::DER)?;
    Ok(Asn1Object::decode(&der, &DecodingOptions::default())?.1)
}
