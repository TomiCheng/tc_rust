use tc_algo::Params;
use tc_algo::params::key::ElGamalPrivateKey;
use tc_asn1::{Asn1Integer, Asn1OctetString, Encode, EncodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use super::decode_all;
use crate::elgamal_parameter::{ELGAMAL_ALGORITHM, integer, object, padded, read};
use crate::pkcs8::Pkcs8Entry;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

// The row of ElGamal, which knows an ElGamalPrivateKey
pub(super) fn elgamal(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn Pkcs8Entry>> {
    vec![Box::new(ElGamal)]
}

struct ElGamal;

impl Pkcs8Entry for ElGamal {
    // ElGamalAlgorithm with the ElGamalParameter p and g, and x as an INTEGER, as Bouncy Castle's
    // PrivateKeyInfoFactory writes it
    fn encode(&self, key: &dyn Params) -> Option<Result<PrivateKeyInfo, AlgoAsn1Error>> {
        let key = key.as_any().downcast_ref::<ElGamalPrivateKey>()?;
        Some(info(key))
    }

    // As Bouncy Castle's PrivateKeyFactory reads it; the parameters are required
    fn decode(&self, info: &PrivateKeyInfo) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
        if ELGAMAL_ALGORITHM != *info.algorithm().algorithm() {
            return None;
        }
        Some(key(info))
    }
}

fn info(key: &ElGamalPrivateKey) -> Result<PrivateKeyInfo, AlgoAsn1Error> {
    let x = Zeroizing::new(integer(key.x()).encode_to_vec(&EncodingOptions::DER)?);
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier::with_parameters(ELGAMAL_ALGORITHM.oid(), object(key.params())),
        Asn1OctetString::new(&x),
    ))
}

fn key(info: &PrivateKeyInfo) -> Result<Box<dyn Params>, AlgoAsn1Error> {
    let (params, width) =
        read(info.algorithm().parameters()).ok_or(AlgoAsn1Error::InvalidPrivateKey)?;
    let x: Asn1Integer = decode_all(info.private_key().as_bytes())?;
    if x.is_negative() {
        return Err(AlgoAsn1Error::InvalidPrivateKey);
    }
    Ok(Box::new(ElGamalPrivateKey::new(padded(&x, width)?, params)))
}
