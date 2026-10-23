//! EC 的金鑰，同 BC 只認 id-ecPublicKey：私鑰是 `PrivateKeyInfo` 裡的 SEC 1 `ECPrivateKey`，公鑰是
//! `SubjectPublicKeyInfo` 的 BIT STRING 裡的 SEC 1 點編碼。
//!
//! 只收具名曲線，演算法參數是曲線的 OID；每條曲線是不同的型別，所以明確寫出的曲線參數與
//! implicitlyCA 不支援。寫出時同 BC 在 `ECPrivateKey` 裡附上曲線與公鑰，點用未壓縮的編碼。
//!
//! tc_asn1 的 OCTET STRING 不會清除內容，所以途中的結構留有私鑰的複本。

use tc_asn1::{
    Asn1BitString, Asn1Object, Asn1OctetString, Asn1Oid, Encode, EncodingOptions, NamedOid,
};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x9::{EcNamedCurve, EcPrivateKey as EcPrivateKeyStructure, X962Parameters};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core::{Curve, Point, PointDecodeError};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_zeroize::Zeroizing;

use super::decode::decode_all;
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, ec_domains};
use crate::{AnyError, SecurityError};

pub(super) const ID_EC_PUBLIC_KEY: NamedOid = NamedOid::new(
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
    "1.2.840.10045.2.1",
    "id-ecPublicKey",
);
/// GM/T 0006 的 SM2 曲線。
const SM2P256V1: NamedOid = NamedOid::new(
    &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d],
    "1.2.156.10197.1.301",
    "sm2p256v1",
);

pub(super) fn private_key(info: &PrivateKeyInfo) -> Result<AnyEcPrivateKey, AnyError> {
    let curve = named_curve(info.algorithm())?;
    let structure: EcPrivateKeyStructure = decode_all(info.private_key().as_bytes())?;
    decode_private(curve, structure.private_key().as_bytes())
}

pub(super) fn public_key(info: &SubjectPublicKeyInfo) -> Result<AnyEcPublicKey, AnyError> {
    let curve = named_curve(info.algorithm())?;
    let bits = info.subject_public_key();
    if bits.unused_bits() != 0 {
        return Err(AnyError::new(SecurityError::InvalidKeyEncoding));
    }
    decode_public(curve, bits.as_bytes())
}

/// 演算法參數裡的曲線 OID。
fn named_curve(algorithm: &AlgorithmIdentifier) -> Result<&Asn1Oid, AnyError> {
    match algorithm.parameters() {
        Some(Asn1Object::Oid(oid)) => Ok(oid),
        _ => Err(AnyError::new(SecurityError::UnknownKeyAlgorithm)),
    }
}

fn algorithm(curve: NamedOid) -> AlgorithmIdentifier {
    AlgorithmIdentifier::with_parameters(ID_EC_PUBLIC_KEY.oid(), curve.oid())
}

/// 階的位元組數，也就是 SEC 1 私鑰的長度。
fn order_length<C: Curve<Scalar = PaddedBigUint>>(g: &C::Point) -> usize {
    g.curve()
        .order()
        .map_or(0, |n| n.bits().div_ceil(8) as usize)
}

/// d 補到階的寬度：常數時間的乘法跑遍純量的整個寬度，寬度不能隨 d 的大小變。
fn private<C: Curve<Scalar = PaddedBigUint>>(
    g: C::Point,
    d: &[u8],
    wrap: fn(Box<EcPrivateKey<C>>) -> AnyEcPrivateKey,
) -> Result<AnyEcPrivateKey, AnyError> {
    let mut buffer = Zeroizing::new(vec![0; order_length::<C>(&g).max(d.len())]);
    let start = buffer.len() - d.len();
    buffer[start..].copy_from_slice(d);
    let Ok(d) = PaddedBigUint::from_be(&buffer[..]);
    let key = EcPrivateKey::new(g, d).map_err(AnyError::new)?;
    Ok(wrap(Box::new(key)))
}

fn public<C: Curve>(
    g: C::Point,
    q: Result<C::Point, PointDecodeError>,
    wrap: fn(Box<EcPublicKey<C>>) -> AnyEcPublicKey,
) -> Result<AnyEcPublicKey, AnyError> {
    let q = q.map_err(AnyError::new)?;
    let key = EcPublicKey::new(g, &q).map_err(AnyError::new)?;
    Ok(wrap(Box::new(key)))
}

/// d 寫成階的長度；公鑰由 d 以常數時間的乘法算出。
fn private_info<C: Curve<Scalar = PaddedBigUint>>(
    curve: NamedOid,
    key: &EcPrivateKey<C>,
    encode: fn(&C::Point) -> Vec<u8>,
) -> Result<PrivateKeyInfo, AnyError> {
    let length = order_length::<C>(key.g());
    let d = Zeroizing::new(ArrayEncoding::<u8>::to_be(key.d()));
    let mut fixed = Zeroizing::new(vec![0; length]);
    let kept = d.len().min(length);
    fixed[length - kept..].copy_from_slice(&d[d.len() - kept..]);
    let q = encode(&C::multiply(key.g(), key.d()));

    let structure = EcPrivateKeyStructure::new(Asn1OctetString::new(&fixed))
        .map_err(AnyError::new)?
        .with_parameters(X962Parameters::NamedCurve(curve.oid()))
        .with_public_key(Asn1BitString::from_bytes(&q));
    let der = structure
        .encode_to_vec(&EncodingOptions::DER)
        .map(Zeroizing::new)
        .map_err(AnyError::new)?;
    Ok(PrivateKeyInfo::new(
        algorithm(curve),
        Asn1OctetString::new(&der),
    ))
}

fn public_info(curve: NamedOid, q: &[u8]) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo::new(algorithm(curve), Asn1BitString::from_bytes(q))
}

// 每條曲線是不同的型別，點的編碼與解碼是各型別自己的方法，所以一條曲線一個分支
macro_rules! named_curves {
    ($($(#[$cfg:meta])* $variant:ident: $oid:expr, $domain:ident;)*) => {
        fn decode_private(curve: &Asn1Oid, d: &[u8]) -> Result<AnyEcPrivateKey, AnyError> {
            $(
                $(#[$cfg])*
                if *curve == $oid {
                    return private(ec_domains::$domain(), d, AnyEcPrivateKey::$variant);
                }
            )*
            Err(AnyError::new(SecurityError::UnknownKeyAlgorithm))
        }

        fn decode_public(curve: &Asn1Oid, encoded: &[u8]) -> Result<AnyEcPublicKey, AnyError> {
            $(
                $(#[$cfg])*
                if *curve == $oid {
                    let g = ec_domains::$domain();
                    let q = g.curve().decode_point(encoded);
                    return public(g, q, AnyEcPublicKey::$variant);
                }
            )*
            Err(AnyError::new(SecurityError::UnknownKeyAlgorithm))
        }

        pub(super) fn private_key_info(key: &AnyEcPrivateKey) -> Result<PrivateKeyInfo, AnyError> {
            match key {
                $(
                    $(#[$cfg])*
                    AnyEcPrivateKey::$variant(key) => {
                        private_info($oid, key, |q| q.encode(false))
                    }
                )*
            }
        }

        pub(super) fn subject_public_key_info(key: &AnyEcPublicKey) -> SubjectPublicKeyInfo {
            match key {
                $(
                    $(#[$cfg])*
                    AnyEcPublicKey::$variant(key) => public_info($oid, &key.q().encode(false)),
                )*
            }
        }
    };
}

named_curves! {
    #[cfg(feature = "ec-small-curves")]
    Secp112r1: EcNamedCurve::SECP112R1, secp112r1;
    #[cfg(feature = "ec-small-curves")]
    Secp112r2: EcNamedCurve::SECP112R2, secp112r2;
    #[cfg(feature = "ec-small-curves")]
    Secp128r1: EcNamedCurve::SECP128R1, secp128r1;
    #[cfg(feature = "ec-small-curves")]
    Secp128r2: EcNamedCurve::SECP128R2, secp128r2;
    #[cfg(feature = "ec-small-curves")]
    Secp160k1: EcNamedCurve::SECP160K1, secp160k1;
    #[cfg(feature = "ec-small-curves")]
    Secp160r1: EcNamedCurve::SECP160R1, secp160r1;
    #[cfg(feature = "ec-small-curves")]
    Secp160r2: EcNamedCurve::SECP160R2, secp160r2;
    #[cfg(feature = "ec-small-curves")]
    Secp192k1: EcNamedCurve::SECP192K1, secp192k1;
    #[cfg(feature = "ec-small-curves")]
    Secp192r1: EcNamedCurve::SECP192R1, secp192r1;
    Secp224k1: EcNamedCurve::SECP224K1, secp224k1;
    Secp224r1: EcNamedCurve::SECP224R1, secp224r1;
    Secp256k1: EcNamedCurve::SECP256K1, secp256k1;
    Secp256r1: EcNamedCurve::SECP256R1, secp256r1;
    Secp384r1: EcNamedCurve::SECP384R1, secp384r1;
    Secp521r1: EcNamedCurve::SECP521R1, secp521r1;
    Sm2p256v1: SM2P256V1, sm2p256v1;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect113r1: EcNamedCurve::SECT113R1, sect113r1;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect113r2: EcNamedCurve::SECT113R2, sect113r2;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect131r1: EcNamedCurve::SECT131R1, sect131r1;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect131r2: EcNamedCurve::SECT131R2, sect131r2;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163k1: EcNamedCurve::SECT163K1, sect163k1;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163r1: EcNamedCurve::SECT163R1, sect163r1;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163r2: EcNamedCurve::SECT163R2, sect163r2;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect193r1: EcNamedCurve::SECT193R1, sect193r1;
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect193r2: EcNamedCurve::SECT193R2, sect193r2;
    #[cfg(feature = "ec-f2m")]
    Sect233k1: EcNamedCurve::SECT233K1, sect233k1;
    #[cfg(feature = "ec-f2m")]
    Sect233r1: EcNamedCurve::SECT233R1, sect233r1;
    #[cfg(feature = "ec-f2m")]
    Sect239k1: EcNamedCurve::SECT239K1, sect239k1;
    #[cfg(feature = "ec-f2m")]
    Sect283k1: EcNamedCurve::SECT283K1, sect283k1;
    #[cfg(feature = "ec-f2m")]
    Sect283r1: EcNamedCurve::SECT283R1, sect283r1;
    #[cfg(feature = "ec-f2m")]
    Sect409k1: EcNamedCurve::SECT409K1, sect409k1;
    #[cfg(feature = "ec-f2m")]
    Sect409r1: EcNamedCurve::SECT409R1, sect409r1;
    #[cfg(feature = "ec-f2m")]
    Sect571k1: EcNamedCurve::SECT571K1, sect571k1;
    #[cfg(feature = "ec-f2m")]
    Sect571r1: EcNamedCurve::SECT571R1, sect571r1;
}
