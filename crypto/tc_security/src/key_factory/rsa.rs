//! RSA（PKCS#1）的金鑰：私鑰是 `PrivateKeyInfo` 的 OCTET STRING 裡的 `RSAPrivateKey`，公鑰是
//! `SubjectPublicKeyInfo` 的 BIT STRING 裡的 `RSAPublicKey`。
//!
//! DER 的整數是最短編碼，長度本身就透露數值有幾個位元組，所以去掉與補回前導零都是變動時間。
//! tc_asn1 的 INTEGER 與 OCTET STRING 不會清除內容，所以途中的結構留有私鑰的複本。

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1OctetString, Asn1Oid, Decode, DecodingOptions,
    Encode, EncodingOptions, NamedOid,
};
use tc_asn1_pkcs::{Pkcs1Algorithm, PrivateKeyInfo, RsaPrivateKey, RsaPublicKey};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_rsa::{RsaKey, RsaKeyOwned, RsaKeyParams, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyParams};
use tc_zeroize::Zeroizing;

use crate::{AnyError, SecurityError};

/// X.509 的 id-ea-rsa，BC 解碼時也收。
const ID_EA_RSA: NamedOid = NamedOid::new(&[0x55, 0x08, 0x01, 0x01], "2.5.8.1.1", "id-ea-rsa");

/// 同 BC 也收 RSASSA-PSS 與 RSAES-OAEP 的 OID，參數不看。
pub(super) fn is_rsa(oid: &Asn1Oid) -> bool {
    [
        Pkcs1Algorithm::RSA_ENCRYPTION,
        ID_EA_RSA,
        Pkcs1Algorithm::RSASSA_PSS,
        Pkcs1Algorithm::RSAES_OAEP,
    ]
    .iter()
    .any(|known| *known == *oid)
}

/// 同 BC 只收兩個質數（version 0）的金鑰。n、e、d 補到模數的寬度，其餘補到質數的寬度。
pub(super) fn private_key(info: &PrivateKeyInfo) -> Result<RsaKey, AnyError> {
    let key: RsaPrivateKey = decode_all(info.private_key().as_bytes())?;
    if key.version() != 0 {
        return Err(AnyError::new(SecurityError::InvalidKeyEncoding));
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

pub(super) fn public_key(info: &SubjectPublicKeyInfo) -> Result<RsaKey, AnyError> {
    let bits = info.subject_public_key();
    if bits.unused_bits() != 0 {
        return Err(AnyError::new(SecurityError::InvalidKeyEncoding));
    }
    let key: RsaPublicKey = decode_all(bits.as_bytes())?;
    let wide = width(key.modulus())?;
    Ok(RsaKey::Core(RsaKeyOwned::new(
        false,
        padded(key.modulus(), wide)?,
        padded(key.public_exponent(), wide)?,
    )))
}

pub(super) fn private_key_info(
    key: &RsaPrivateCrtKeyOwned<PaddedBigUint>,
) -> Result<PrivateKeyInfo, AnyError> {
    let structure = RsaPrivateKey::new(
        integer(key.modulus()),
        integer(key.public_exponent()),
        integer(key.exponent()),
        integer(key.p()),
        integer(key.q()),
        integer(key.dp()),
        integer(key.dq()),
        integer(key.q_inv()),
    )
    .map_err(AnyError::new)?;
    let der = structure
        .encode_to_vec(&EncodingOptions::DER)
        .map(Zeroizing::new)
        .map_err(AnyError::new)?;
    Ok(PrivateKeyInfo::new(algorithm(), Asn1OctetString::new(&der)))
}

pub(super) fn subject_public_key_info(
    key: &RsaKeyOwned<PaddedBigUint>,
) -> Result<SubjectPublicKeyInfo, AnyError> {
    let der = RsaPublicKey::new(integer(key.modulus()), integer(key.exponent()))
        .and_then(|structure| structure.encode_to_vec(&EncodingOptions::DER))
        .map_err(AnyError::new)?;
    Ok(SubjectPublicKeyInfo::new(
        algorithm(),
        Asn1BitString::from_bytes(&der),
    ))
}

/// 同 BC 寫 rsaEncryption 加 NULL 參數。
fn algorithm() -> AlgorithmIdentifier {
    AlgorithmIdentifier::with_null(Pkcs1Algorithm::RSA_ENCRYPTION.oid())
}

fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, AnyError> {
    let (consumed, value) = T::decode(bytes, &DecodingOptions::default()).map_err(AnyError::new)?;
    if consumed != bytes.len() {
        return Err(AnyError::new(Asn1Error::TrailingData));
    }
    Ok(value)
}

fn width(value: &Asn1Integer) -> Result<usize, AnyError> {
    value
        .as_unsigned_bytes()
        .map(<[u8]>::len)
        .map_err(AnyError::new)
}

fn padded(value: &Asn1Integer, width: usize) -> Result<PaddedBigUint, AnyError> {
    let bytes = value.as_unsigned_bytes().map_err(AnyError::new)?;
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
