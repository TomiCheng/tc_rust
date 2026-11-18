use tc_algo::Params;
use tc_algo::params::key::rsa::RsaKey;
use tc_asn1::{Asn1Integer, Asn1OctetString, Asn1Oid, Encode, EncodingOptions, NamedOid};
use tc_asn1_pkcs::{Pkcs1Algorithm, PrivateKeyInfo, RsaPrivateKey};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_rsa::{RsaKeyParams, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyParams};
use tc_zeroize::Zeroizing;

use super::decode_all;
use crate::operator::private_key_info::PrivateKeyInfoEntry;
use crate::{DefaultPkcsOperatorContext, PkcsError};

// X.509's id-ea-rsa, which Bouncy Castle also reads
const ID_EA_RSA: NamedOid = NamedOid::new(&[0x55, 0x08, 0x01, 0x01], "2.5.8.1.1", "id-ea-rsa");

// The row of RSA, which knows an RsaKey with its CRT values
pub(super) fn rsa(_context: &DefaultPkcsOperatorContext) -> Vec<Box<dyn PrivateKeyInfoEntry>> {
    vec![Box::new(Rsa)]
}

struct Rsa;

impl PrivateKeyInfoEntry for Rsa {
    // rsaEncryption with NULL parameters and the RSAPrivateKey, as Bouncy Castle's
    // PrivateKeyInfoFactory writes it. A private key without its CRT values is refused: PKCS#1 has
    // no form for it, where Bouncy Castle writes zeros in their place
    fn encode(&self, key: &dyn Params) -> Option<Result<PrivateKeyInfo, PkcsError>> {
        let key = key.as_any().downcast_ref::<RsaKey>()?;
        Some(match key {
            RsaKey::Crt(key) => info(key),
            _ if key.is_private_key() => Err(PkcsError::InvalidPrivateKey),
            _ => Err(PkcsError::NotPrivateKey),
        })
    }

    // As Bouncy Castle's PrivateKeyFactory, the OIDs of RSASSA-PSS and RSAES-OAEP are read as RSA
    // too, and a key of two primes alone, version 0
    fn decode(&self, info: &PrivateKeyInfo) -> Option<Result<Box<dyn Params>, PkcsError>> {
        if !is_rsa(info.algorithm().algorithm()) {
            return None;
        }
        Some(private_key(info).map(|key| Box::new(key) as Box<dyn Params>))
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

fn info(key: &RsaPrivateCrtKeyOwned<PaddedBigUint>) -> Result<PrivateKeyInfo, PkcsError> {
    let structure = RsaPrivateKey::new(
        integer(key.modulus()),
        integer(key.public_exponent()),
        integer(key.exponent()),
        integer(key.p()),
        integer(key.q()),
        integer(key.dp()),
        integer(key.dq()),
        integer(key.q_inv()),
    )?;
    let der = Zeroizing::new(structure.encode_to_vec(&EncodingOptions::DER)?);
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier::with_null(Pkcs1Algorithm::RSA_ENCRYPTION.oid()),
        Asn1OctetString::new(&der),
    ))
}

// n, e and d are padded to the width of the modulus, the rest to that of the primes, as the keys
// tc_rsa generates are
fn private_key(info: &PrivateKeyInfo) -> Result<RsaKey, PkcsError> {
    let key: RsaPrivateKey = decode_all(info.private_key().as_bytes())?;
    if key.version() != 0 {
        return Err(PkcsError::InvalidPrivateKey);
    }
    let wide = width(key.modulus())?;
    let half = width(key.prime1())?.max(width(key.prime2())?);
    Ok(RsaKey::Crt(RsaPrivateCrtKeyOwned::new(
        padded(key.modulus(), wide)?,
        padded(key.public_exponent(), wide)?,
        padded(key.private_exponent(), wide)?,
        padded(key.prime1(), half)?,
        padded(key.prime2(), half)?,
        padded(key.exponent1(), half)?,
        padded(key.exponent2(), half)?,
        padded(key.coefficient(), half)?,
    )))
}

fn width(value: &Asn1Integer) -> Result<usize, PkcsError> {
    Ok(value.as_unsigned_bytes()?.len())
}

fn padded(value: &Asn1Integer, width: usize) -> Result<PaddedBigUint, PkcsError> {
    let bytes = value.as_unsigned_bytes()?;
    let mut buffer = Zeroizing::new(vec![0; width.max(bytes.len())]);
    let start = buffer.len() - bytes.len();
    buffer[start..].copy_from_slice(bytes);
    let Ok(value) = PaddedBigUint::from_be(&buffer[..]);
    Ok(value)
}

fn integer(value: &PaddedBigUint) -> Asn1Integer {
    let bytes = Zeroizing::new(ArrayEncoding::<u8>::to_be(value));
    Asn1Integer::from_unsigned_bytes(&bytes)
}
