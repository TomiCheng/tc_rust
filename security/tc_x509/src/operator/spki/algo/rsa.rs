use tc_algo::Params;
use tc_algo::params::{RsaKey, RsaKeyParams};
use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Oid, Decode, DecodingOptions, Encode,
    EncodingOptions, NamedOid,
};
use tc_asn1_pkcs::{Pkcs1Algorithm, RsaPublicKey};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_rsa::RsaKeyOwned;

use crate::operator::spki::SpkiEntry;
use crate::{DefaultX509OperatorContext, X509Error};

// X.509's id-ea-rsa, which Bouncy Castle also reads
const ID_EA_RSA: NamedOid = NamedOid::new(&[0x55, 0x08, 0x01, 0x01], "2.5.8.1.1", "id-ea-rsa");

// The row of RSA, which knows an RsaKey
pub(super) fn rsa(_context: &DefaultX509OperatorContext) -> Vec<Box<dyn SpkiEntry>> {
    vec![Box::new(Rsa)]
}

struct Rsa;

impl SpkiEntry for Rsa {
    // rsaEncryption with NULL parameters, and the RSAPublicKey in the BIT STRING, as Bouncy
    // Castle's SubjectPublicKeyInfoFactory writes for any RSA key
    fn encode(&self, key: &dyn Params) -> Option<Result<SubjectPublicKeyInfo, X509Error>> {
        let key = key.as_any().downcast_ref::<RsaKey>()?;
        if key.is_private_key() {
            return Some(Err(X509Error::NotPublicKey));
        }
        Some(spki(key))
    }

    // As Bouncy Castle's PublicKeyFactory, the OIDs of RSASSA-PSS and RSAES-OAEP are read as RSA
    // too, without looking at their parameters
    fn decode(&self, spki: &SubjectPublicKeyInfo) -> Option<Result<Box<dyn Params>, X509Error>> {
        if !is_rsa(spki.algorithm().algorithm()) {
            return None;
        }
        Some(public_key(spki).map(|key| Box::new(key) as Box<dyn Params>))
    }
}

fn is_rsa(oid: &Asn1Oid) -> bool {
    [
        Pkcs1Algorithm::RSA_ENCRYPTION,
        ID_EA_RSA,
        Pkcs1Algorithm::RSASSA_PSS,
        Pkcs1Algorithm::RSAES_OAEP,
    ]
    .iter()
    .any(|known| *known == *oid)
}

fn spki(key: &RsaKey) -> Result<SubjectPublicKeyInfo, X509Error> {
    let der = RsaPublicKey::new(integer(key.modulus()), integer(key.exponent()))?
        .encode_to_vec(&EncodingOptions::DER)?;
    Ok(SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::with_null(Pkcs1Algorithm::RSA_ENCRYPTION.oid()),
        Asn1BitString::from_bytes(&der),
    ))
}

// The modulus and the exponent are padded to the width of the modulus, as the keys tc_rsa
// generates are
fn public_key(spki: &SubjectPublicKeyInfo) -> Result<RsaKey, X509Error> {
    let bits = spki.subject_public_key();
    if bits.unused_bits() != 0 {
        return Err(X509Error::InvalidPublicKey);
    }
    let bytes = bits.as_bytes();
    let (used, key) = RsaPublicKey::decode(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    let width = key.modulus().as_unsigned_bytes()?.len();
    Ok(RsaKey::Core(RsaKeyOwned::new(
        false,
        padded(key.modulus(), width)?,
        padded(key.public_exponent(), width)?,
    )))
}

fn integer(value: &PaddedBigUint) -> Asn1Integer {
    Asn1Integer::from_unsigned_bytes(&ArrayEncoding::<u8>::to_be(value))
}

fn padded(value: &Asn1Integer, width: usize) -> Result<PaddedBigUint, X509Error> {
    let bytes = value.as_unsigned_bytes()?;
    let mut buffer = vec![0; width.max(bytes.len())];
    let start = buffer.len() - bytes.len();
    buffer[start..].copy_from_slice(bytes);
    let Ok(value) = PaddedBigUint::from_be(&buffer[..]);
    Ok(value)
}
