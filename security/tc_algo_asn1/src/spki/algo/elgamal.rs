use tc_algo::Params;
use tc_algo::params::key::ElGamalPublicKey;
use tc_asn1::{Asn1BitString, Asn1Integer, Encode, EncodingOptions};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::der::decode_all;
use crate::elgamal_parameter::{ELGAMAL_ALGORITHM, integer, object, padded, read};
use crate::spki::SpkiEntry;
use crate::{AlgoAsn1Error, DefaultAlgoAsn1Context};

// The row of ElGamal, which knows an ElGamalPublicKey
pub(super) fn elgamal(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>> {
    vec![Box::new(ElGamal)]
}

struct ElGamal;

impl SpkiEntry for ElGamal {
    // ElGamalAlgorithm with the ElGamalParameter p and g, and y as an INTEGER in the BIT STRING, as
    // Bouncy Castle's SubjectPublicKeyInfoFactory writes it
    fn encode(&self, key: &dyn Params) -> Option<Result<SubjectPublicKeyInfo, AlgoAsn1Error>> {
        let key = key.as_any().downcast_ref::<ElGamalPublicKey>()?;
        Some(spki(key))
    }

    // As Bouncy Castle's PublicKeyFactory reads it; the parameters are required
    fn decode(
        &self,
        spki: &SubjectPublicKeyInfo,
    ) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>> {
        if ELGAMAL_ALGORITHM != *spki.algorithm().algorithm() {
            return None;
        }
        Some(key(spki))
    }
}

fn spki(key: &ElGamalPublicKey) -> Result<SubjectPublicKeyInfo, AlgoAsn1Error> {
    let y = integer(key.y()).encode_to_vec(&EncodingOptions::DER)?;
    Ok(SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::with_parameters(ELGAMAL_ALGORITHM.oid(), object(key.params())),
        Asn1BitString::from_bytes(&y),
    ))
}

fn key(spki: &SubjectPublicKeyInfo) -> Result<Box<dyn Params>, AlgoAsn1Error> {
    let (params, width) =
        read(spki.algorithm().parameters()).ok_or(AlgoAsn1Error::InvalidPublicKey)?;
    let bits = spki.subject_public_key();
    if bits.unused_bits() != 0 {
        return Err(AlgoAsn1Error::InvalidPublicKey);
    }
    let y: Asn1Integer = decode_all(bits.as_bytes())?;
    if y.is_negative() {
        return Err(AlgoAsn1Error::InvalidPublicKey);
    }
    Ok(Box::new(ElGamalPublicKey::new(padded(&y, width)?, params)))
}
