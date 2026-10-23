//! CFRG 曲線（RFC 8410）的金鑰：私鑰是 `PrivateKeyInfo` 的 OCTET STRING 裡再包一層 OCTET STRING，
//! 公鑰是 `SubjectPublicKeyInfo` 的 BIT STRING，兩者都是裸金鑰。
//!
//! tc_asn1 的 OCTET STRING 不會清除內容，所以解碼與編碼途中的 `PrivateKeyInfo` 留有私鑰的複本。

use tc_asn1::{Asn1BitString, Asn1OctetString, Encode, EncodingOptions, NamedOid};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_zeroize::Zeroizing;

use super::decode::decode_all;
use crate::{AnyError, SecurityError};

#[cfg(feature = "x25519")]
pub(super) const X25519: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6e], "1.3.101.110", "id-X25519");
/// Cryptlib 的 X25519，BC 解碼時也收。
#[cfg(feature = "x25519")]
pub(super) const CRYPTLIB_X25519: NamedOid = NamedOid::new(
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    "1.3.6.1.4.1.3029.1.5.1",
    "curvey25519",
);
#[cfg(feature = "x448")]
pub(super) const X448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x6f], "1.3.101.111", "id-X448");
#[cfg(feature = "ed25519")]
pub(super) const ED25519: NamedOid =
    NamedOid::new(&[0x2b, 0x65, 0x70], "1.3.101.112", "id-Ed25519");
/// GnuPG 的 Ed25519，BC 解碼時也收。
#[cfg(feature = "ed25519")]
pub(super) const GNU_ED25519: NamedOid = NamedOid::new(
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01],
    "1.3.6.1.4.1.11591.15.1",
    "Ed25519",
);
#[cfg(feature = "ed448")]
pub(super) const ED448: NamedOid = NamedOid::new(&[0x2b, 0x65, 0x71], "1.3.101.113", "id-Ed448");

/// 取出私鑰。`bare` 時同 BC 也收 Java 11 沒包內層 OCTET STRING、長度剛好是金鑰長度的寫法。
pub(super) fn private_key<const N: usize>(
    info: &PrivateKeyInfo,
    bare: bool,
) -> Result<Zeroizing<[u8; N]>, AnyError> {
    let octets = info.private_key().as_bytes();
    if bare && octets.len() == N {
        return to_array(octets).map(Zeroizing::new);
    }
    let inner: Asn1OctetString = decode_all(octets)?;
    to_array(inner.as_bytes()).map(Zeroizing::new)
}

/// 取出公鑰；BIT STRING 不能有未用位元。
pub(super) fn public_key<const N: usize>(info: &SubjectPublicKeyInfo) -> Result<[u8; N], AnyError> {
    let bits = info.subject_public_key();
    if bits.unused_bits() != 0 {
        return Err(AnyError::new(SecurityError::InvalidKeyEncoding));
    }
    to_array(bits.as_bytes())
}

/// 同 BC 附上公鑰，所以是 RFC 5958 的 version 1。
pub(super) fn private_key_info(
    oid: NamedOid,
    private: &[u8],
    public: &[u8],
) -> Result<PrivateKeyInfo, AnyError> {
    let inner = Asn1OctetString::new(private)
        .encode_to_vec(&EncodingOptions::DER)
        .map(Zeroizing::new)
        .map_err(AnyError::new)?;
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier::new(oid.oid()),
        Asn1OctetString::new(&inner),
    )
    .with_public_key(Asn1BitString::from_bytes(public)))
}

pub(super) fn subject_public_key_info(oid: NamedOid, public: &[u8]) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new(oid.oid()),
        Asn1BitString::from_bytes(public),
    )
}

fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AnyError> {
    bytes
        .try_into()
        .map_err(|_| AnyError::new(SecurityError::InvalidKeyEncoding))
}
