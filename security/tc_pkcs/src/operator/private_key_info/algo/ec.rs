use std::sync::OnceLock;

use tc_algo::Params;
use tc_algo::params::EcPrivateKey;
use tc_asn1::{
    Asn1BitString, Asn1Object, Asn1OctetString, Asn1Oid, Encode, EncodingOptions, NamedOid,
};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x9::ec::{EcPrivateKey as EcPrivateKeyStructure, X962Parameters};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core::{Curve, Point};
use tc_f2m_curve::{F2mCtCurve, F2mCtPoint};
use tc_f2m_custom::{
    SecT113FieldElement, SecT131FieldElement, SecT163FieldElement, SecT193FieldElement,
    SecT233FieldElement, SecT239FieldElement, SecT283FieldElement, SecT409FieldElement,
    SecT571FieldElement, SecTCtCurve, SecTCtPoint,
};
use tc_fp_curve::{FpCtCurve, FpCtPoint, FpField};
use tc_fp_custom::{
    SM2P256V1FieldElement, SecP128R1FieldElement, SecP160R1FieldElement, SecP160R2FieldElement,
    SecP192K1FieldElement, SecP192R1FieldElement, SecP224K1FieldElement, SecP224R1FieldElement,
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve, SecPCtPoint,
};
use tc_zeroize::Zeroizing;

use super::decode_all;
use crate::operator::private_key_info::PrivateKeyInfoEntry;
use crate::{DefaultPkcsOperatorContext, PkcsError};

// id-ecPublicKey of RFC 5480
const ID_EC_PUBLIC_KEY: NamedOid = NamedOid::new(
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
    "1.2.840.10045.2.1",
    "id-ecPublicKey",
);

// The row of EC, which knows the EcPrivateKey of each named curve tc_algo generates on. The OIDs
// of the curves are PKCS#8's own table, as tc_x509 keeps one for SPKI: a curve may go by another
// OID elsewhere. Many curves share a type, so a key is matched by its generator, whose equality
// takes in the curve's parameters, not by its type alone
pub(super) fn ec(_context: &DefaultPkcsOperatorContext) -> Vec<Box<dyn PrivateKeyInfoEntry>> {
    vec![Box::new(Ec)]
}

struct Ec;

impl PrivateKeyInfoEntry for Ec {
    // id-ecPublicKey with the curve's OID, and the ECPrivateKey of SEC 1 with d as long as the
    // order, the curve and the uncompressed public key, as Bouncy Castle's PrivateKeyInfoFactory
    // writes a key of a named curve
    fn encode(&self, key: &dyn Params) -> Option<Result<PrivateKeyInfo, PkcsError>> {
        let (oid, d, q) = CURVES
            .iter()
            .find_map(|curve| (curve.encode)(key).map(|(d, q)| (curve.oid, d, q)))?;
        Some(info(oid, &d, &q))
    }

    // A named curve alone, from the algorithm's parameters: explicit parameters and implicitlyCA
    // are refused, as the curve has to be one tc_algo has a type for
    fn decode(&self, info: &PrivateKeyInfo) -> Option<Result<Box<dyn Params>, PkcsError>> {
        if ID_EC_PUBLIC_KEY != *info.algorithm().algorithm() {
            return None;
        }
        Some(decode(info))
    }
}

fn info(oid: &str, d: &[u8], q: &[u8]) -> Result<PrivateKeyInfo, PkcsError> {
    let curve: Asn1Oid = oid.parse().expect("a valid OID");
    let structure = EcPrivateKeyStructure::new(Asn1OctetString::new(d))?
        .with_parameters(X962Parameters::NamedCurve(curve.clone()))
        .with_public_key(Asn1BitString::from_bytes(q));
    let der = Zeroizing::new(structure.encode_to_vec(&EncodingOptions::DER)?);
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier::with_parameters(ID_EC_PUBLIC_KEY.oid(), Asn1Object::Oid(curve)),
        Asn1OctetString::new(&der),
    ))
}

fn decode(info: &PrivateKeyInfo) -> Result<Box<dyn Params>, PkcsError> {
    let Some(Asn1Object::Oid(curve)) = info.algorithm().parameters() else {
        return Err(PkcsError::InvalidPrivateKey);
    };
    let entry = CURVES
        .iter()
        .find(|entry| entry.oid.parse::<Asn1Oid>().is_ok_and(|oid| &oid == curve))
        .ok_or(PkcsError::UnknownPrivateKey)?;
    let structure: EcPrivateKeyStructure = decode_all(info.private_key().as_bytes())?;
    (entry.decode)(structure.private_key().as_bytes())
}

// A point that encodes as SEC 1
trait Sec1: Point + Sized {
    fn encode_sec1(&self) -> Vec<u8>;
}

impl Sec1 for FpCtPoint<'static> {
    fn encode_sec1(&self) -> Vec<u8> {
        self.encode(false)
    }
}

impl Sec1 for F2mCtPoint<'static> {
    fn encode_sec1(&self) -> Vec<u8> {
        self.encode(false)
    }
}

// The fields of tc_fp_custom and tc_f2m_custom name their bound in a module of their own, so each
// field has its implementation
macro_rules! sec1 {
    ($($point:ident<$field:ident>),* $(,)?) => {
        $(
            impl Sec1 for $point<'static, $field> {
                fn encode_sec1(&self) -> Vec<u8> {
                    self.encode(false)
                }
            }
        )*
    };
}

sec1!(
    SecPCtPoint<SecP128R1FieldElement>,
    SecPCtPoint<SecP160R1FieldElement>,
    SecPCtPoint<SecP160R2FieldElement>,
    SecPCtPoint<SecP192K1FieldElement>,
    SecPCtPoint<SecP192R1FieldElement>,
    SecPCtPoint<SecP224K1FieldElement>,
    SecPCtPoint<SecP224R1FieldElement>,
    SecPCtPoint<SecP256K1FieldElement>,
    SecPCtPoint<SecP256R1FieldElement>,
    SecPCtPoint<SecP384R1FieldElement>,
    SecPCtPoint<SecP521R1FieldElement>,
    SecPCtPoint<SM2P256V1FieldElement>,
    SecTCtPoint<SecT113FieldElement>,
    SecTCtPoint<SecT131FieldElement>,
    SecTCtPoint<SecT163FieldElement>,
    SecTCtPoint<SecT193FieldElement>,
    SecTCtPoint<SecT233FieldElement>,
    SecTCtPoint<SecT239FieldElement>,
    SecTCtPoint<SecT283FieldElement>,
    SecTCtPoint<SecT409FieldElement>,
    SecTCtPoint<SecT571FieldElement>,
);

// The length of the order in bytes, that of d in SEC 1
fn order_length<C: Curve<Scalar = PaddedBigUint>>(g: &C::Point) -> usize {
    g.curve()
        .order()
        .map_or(0, |n| n.bits().div_ceil(8) as usize)
}

// d as long as the order, and the public point, when `key` is a private key on the curve of `g`
fn encode<C>(key: &dyn Params, g: fn() -> C::Point) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    C::Point: Sec1,
{
    let key = key.as_any().downcast_ref::<EcPrivateKey<C>>()?;
    if *key.g() != g() {
        return None;
    }
    let length = order_length::<C>(key.g());
    let d = Zeroizing::new(ArrayEncoding::<u8>::to_be(key.d()));
    let mut fixed = Zeroizing::new(vec![0; length]);
    let kept = d.len().min(length);
    fixed[length - kept..].copy_from_slice(&d[d.len() - kept..]);
    let q = C::multiply(key.g(), key.d()).encode_sec1();
    Some((fixed, q))
}

// d is padded to the width of the order, since the constant-time multiplication runs over the
// whole width of the scalar
fn decode_on<C>(d: &[u8], g: fn() -> C::Point) -> Result<Box<dyn Params>, PkcsError>
where
    C: Curve<Scalar = PaddedBigUint> + 'static,
    EcPrivateKey<C>: Params,
{
    let g = g();
    let mut buffer = Zeroizing::new(vec![0; order_length::<C>(&g).max(d.len())]);
    let start = buffer.len() - d.len();
    buffer[start..].copy_from_slice(d);
    let Ok(d) = PaddedBigUint::from_be(&buffer[..]);
    let key = EcPrivateKey::new(g, d).map_err(|_| PkcsError::InvalidPrivateKey)?;
    Ok(Box::new(key))
}

type EncodeKey = fn(&dyn Params) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)>;

struct Entry {
    oid: &'static str,
    encode: EncodeKey,
    decode: fn(&[u8]) -> Result<Box<dyn Params>, PkcsError>,
}

macro_rules! curve {
    ($oid:literal, $curve:ty, $g:ident) => {
        Entry {
            oid: $oid,
            encode: |key| encode::<$curve>(key, $g),
            decode: |d| decode_on::<$curve>(d, $g),
        }
    };
}

// The named curves of tc_algo, by the OIDs PKCS#8 gives them
const CURVES: &[Entry] = &[
    curve!("1.3.132.0.6", &'static FpCtCurve<'static>, secp112r1), // secp112r1
    curve!("1.3.132.0.7", &'static FpCtCurve<'static>, secp112r2), // secp112r2
    curve!(
        "1.3.132.0.28",
        &'static SecPCtCurve<SecP128R1FieldElement>,
        secp128r1
    ), // secp128r1
    curve!("1.3.132.0.29", &'static FpCtCurve<'static>, secp128r2), // secp128r2
    curve!(
        "1.3.132.0.9",
        &'static SecPCtCurve<SecP160R2FieldElement>,
        secp160k1
    ), // secp160k1
    curve!(
        "1.3.132.0.8",
        &'static SecPCtCurve<SecP160R1FieldElement>,
        secp160r1
    ), // secp160r1
    curve!(
        "1.3.132.0.30",
        &'static SecPCtCurve<SecP160R2FieldElement>,
        secp160r2
    ), // secp160r2
    curve!(
        "1.3.132.0.31",
        &'static SecPCtCurve<SecP192K1FieldElement>,
        secp192k1
    ), // secp192k1
    curve!(
        "1.2.840.10045.3.1.1",
        &'static SecPCtCurve<SecP192R1FieldElement>,
        secp192r1
    ), // secp192r1
    curve!(
        "1.3.132.0.32",
        &'static SecPCtCurve<SecP224K1FieldElement>,
        secp224k1
    ), // secp224k1
    curve!(
        "1.3.132.0.33",
        &'static SecPCtCurve<SecP224R1FieldElement>,
        secp224r1
    ), // secp224r1
    curve!(
        "1.3.132.0.10",
        &'static SecPCtCurve<SecP256K1FieldElement>,
        secp256k1
    ), // secp256k1
    curve!(
        "1.2.840.10045.3.1.7",
        &'static SecPCtCurve<SecP256R1FieldElement>,
        secp256r1
    ), // secp256r1
    curve!(
        "1.3.132.0.34",
        &'static SecPCtCurve<SecP384R1FieldElement>,
        secp384r1
    ), // secp384r1
    curve!(
        "1.3.132.0.35",
        &'static SecPCtCurve<SecP521R1FieldElement>,
        secp521r1
    ), // secp521r1
    curve!(
        "1.3.132.0.4",
        &'static SecTCtCurve<SecT113FieldElement>,
        sect113r1
    ), // sect113r1
    curve!(
        "1.3.132.0.5",
        &'static SecTCtCurve<SecT113FieldElement>,
        sect113r2
    ), // sect113r2
    curve!(
        "1.3.132.0.22",
        &'static SecTCtCurve<SecT131FieldElement>,
        sect131r1
    ), // sect131r1
    curve!(
        "1.3.132.0.23",
        &'static SecTCtCurve<SecT131FieldElement>,
        sect131r2
    ), // sect131r2
    curve!(
        "1.3.132.0.1",
        &'static SecTCtCurve<SecT163FieldElement>,
        sect163k1
    ), // sect163k1
    curve!(
        "1.3.132.0.2",
        &'static SecTCtCurve<SecT163FieldElement>,
        sect163r1
    ), // sect163r1
    curve!(
        "1.3.132.0.15",
        &'static SecTCtCurve<SecT163FieldElement>,
        sect163r2
    ), // sect163r2
    curve!(
        "1.3.132.0.24",
        &'static SecTCtCurve<SecT193FieldElement>,
        sect193r1
    ), // sect193r1
    curve!(
        "1.3.132.0.25",
        &'static SecTCtCurve<SecT193FieldElement>,
        sect193r2
    ), // sect193r2
    curve!(
        "1.3.132.0.26",
        &'static SecTCtCurve<SecT233FieldElement>,
        sect233k1
    ), // sect233k1
    curve!(
        "1.3.132.0.27",
        &'static SecTCtCurve<SecT233FieldElement>,
        sect233r1
    ), // sect233r1
    curve!(
        "1.3.132.0.3",
        &'static SecTCtCurve<SecT239FieldElement>,
        sect239k1
    ), // sect239k1
    curve!(
        "1.3.132.0.16",
        &'static SecTCtCurve<SecT283FieldElement>,
        sect283k1
    ), // sect283k1
    curve!(
        "1.3.132.0.17",
        &'static SecTCtCurve<SecT283FieldElement>,
        sect283r1
    ), // sect283r1
    curve!(
        "1.3.132.0.36",
        &'static SecTCtCurve<SecT409FieldElement>,
        sect409k1
    ), // sect409k1
    curve!(
        "1.3.132.0.37",
        &'static SecTCtCurve<SecT409FieldElement>,
        sect409r1
    ), // sect409r1
    curve!(
        "1.3.132.0.38",
        &'static SecTCtCurve<SecT571FieldElement>,
        sect571k1
    ), // sect571k1
    curve!(
        "1.3.132.0.39",
        &'static SecTCtCurve<SecT571FieldElement>,
        sect571r1
    ), // sect571r1
    curve!(
        "1.2.840.10045.3.1.2",
        &'static FpCtCurve<'static>,
        prime192v2
    ), // prime192v2
    curve!(
        "1.2.840.10045.3.1.3",
        &'static FpCtCurve<'static>,
        prime192v3
    ), // prime192v3
    curve!(
        "1.2.840.10045.3.1.4",
        &'static FpCtCurve<'static>,
        prime239v1
    ), // prime239v1
    curve!(
        "1.2.840.10045.3.1.5",
        &'static FpCtCurve<'static>,
        prime239v2
    ), // prime239v2
    curve!(
        "1.2.840.10045.3.1.6",
        &'static FpCtCurve<'static>,
        prime239v3
    ), // prime239v3
    curve!("1.2.840.10045.3.0.1", &'static F2mCtCurve, c2pnb163v1), // c2pnb163v1
    curve!("1.2.840.10045.3.0.2", &'static F2mCtCurve, c2pnb163v2), // c2pnb163v2
    curve!("1.2.840.10045.3.0.3", &'static F2mCtCurve, c2pnb163v3), // c2pnb163v3
    curve!("1.2.840.10045.3.0.4", &'static F2mCtCurve, c2pnb176w1), // c2pnb176w1
    curve!("1.2.840.10045.3.0.5", &'static F2mCtCurve, c2tnb191v1), // c2tnb191v1
    curve!("1.2.840.10045.3.0.6", &'static F2mCtCurve, c2tnb191v2), // c2tnb191v2
    curve!("1.2.840.10045.3.0.7", &'static F2mCtCurve, c2tnb191v3), // c2tnb191v3
    curve!("1.2.840.10045.3.0.10", &'static F2mCtCurve, c2pnb208w1), // c2pnb208w1
    curve!("1.2.840.10045.3.0.11", &'static F2mCtCurve, c2tnb239v1), // c2tnb239v1
    curve!("1.2.840.10045.3.0.12", &'static F2mCtCurve, c2tnb239v2), // c2tnb239v2
    curve!("1.2.840.10045.3.0.13", &'static F2mCtCurve, c2tnb239v3), // c2tnb239v3
    curve!("1.2.840.10045.3.0.16", &'static F2mCtCurve, c2pnb272w1), // c2pnb272w1
    curve!("1.2.840.10045.3.0.17", &'static F2mCtCurve, c2pnb304w1), // c2pnb304w1
    curve!("1.2.840.10045.3.0.18", &'static F2mCtCurve, c2tnb359v1), // c2tnb359v1
    curve!("1.2.840.10045.3.0.19", &'static F2mCtCurve, c2pnb368w1), // c2pnb368w1
    curve!("1.2.840.10045.3.0.20", &'static F2mCtCurve, c2tnb431r1), // c2tnb431r1
    curve!(
        "1.3.36.3.3.2.8.1.1.1",
        &'static FpCtCurve<'static>,
        brainpoolp160r1
    ), // brainpoolP160r1
    curve!(
        "1.3.36.3.3.2.8.1.1.2",
        &'static FpCtCurve<'static>,
        brainpoolp160t1
    ), // brainpoolP160t1
    curve!(
        "1.3.36.3.3.2.8.1.1.3",
        &'static FpCtCurve<'static>,
        brainpoolp192r1
    ), // brainpoolP192r1
    curve!(
        "1.3.36.3.3.2.8.1.1.4",
        &'static FpCtCurve<'static>,
        brainpoolp192t1
    ), // brainpoolP192t1
    curve!(
        "1.3.36.3.3.2.8.1.1.5",
        &'static FpCtCurve<'static>,
        brainpoolp224r1
    ), // brainpoolP224r1
    curve!(
        "1.3.36.3.3.2.8.1.1.6",
        &'static FpCtCurve<'static>,
        brainpoolp224t1
    ), // brainpoolP224t1
    curve!(
        "1.3.36.3.3.2.8.1.1.7",
        &'static FpCtCurve<'static>,
        brainpoolp256r1
    ), // brainpoolP256r1
    curve!(
        "1.3.36.3.3.2.8.1.1.8",
        &'static FpCtCurve<'static>,
        brainpoolp256t1
    ), // brainpoolP256t1
    curve!(
        "1.3.36.3.3.2.8.1.1.9",
        &'static FpCtCurve<'static>,
        brainpoolp320r1
    ), // brainpoolP320r1
    curve!(
        "1.3.36.3.3.2.8.1.1.10",
        &'static FpCtCurve<'static>,
        brainpoolp320t1
    ), // brainpoolP320t1
    curve!(
        "1.3.36.3.3.2.8.1.1.11",
        &'static FpCtCurve<'static>,
        brainpoolp384r1
    ), // brainpoolP384r1
    curve!(
        "1.3.36.3.3.2.8.1.1.12",
        &'static FpCtCurve<'static>,
        brainpoolp384t1
    ), // brainpoolP384t1
    curve!(
        "1.3.36.3.3.2.8.1.1.13",
        &'static FpCtCurve<'static>,
        brainpoolp512r1
    ), // brainpoolP512r1
    curve!(
        "1.3.36.3.3.2.8.1.1.14",
        &'static FpCtCurve<'static>,
        brainpoolp512t1
    ), // brainpoolP512t1
    curve!(
        "1.2.250.1.223.101.256.1",
        &'static FpCtCurve<'static>,
        frp256v1
    ), // FRP256v1
    curve!(
        "1.2.643.2.2.35.1",
        &'static FpCtCurve<'static>,
        gostr3410_2001_cryptopro_a
    ), // GostR3410-2001-CryptoPro-A
    curve!(
        "1.2.643.2.2.35.2",
        &'static FpCtCurve<'static>,
        gostr3410_2001_cryptopro_b
    ), // GostR3410-2001-CryptoPro-B
    curve!(
        "1.2.643.2.2.35.3",
        &'static FpCtCurve<'static>,
        gostr3410_2001_cryptopro_c
    ), // GostR3410-2001-CryptoPro-C
    curve!(
        "1.2.643.2.2.36.0",
        &'static FpCtCurve<'static>,
        gostr3410_2001_cryptopro_xcha
    ), // GostR3410-2001-CryptoPro-XchA
    curve!(
        "1.2.643.2.2.36.1",
        &'static FpCtCurve<'static>,
        gostr3410_2001_cryptopro_xchb
    ), // GostR3410-2001-CryptoPro-XchB
    curve!(
        "1.2.643.7.1.2.1.1.1",
        &'static FpCtCurve<'static>,
        tc26_gost_3410_12_256_paramseta
    ), // Tc26-Gost-3410-12-256-paramSetA
    curve!(
        "1.2.643.7.1.2.1.1.2",
        &'static FpCtCurve<'static>,
        tc26_gost_3410_12_256_paramsetb
    ), // Tc26-Gost-3410-12-256-paramSetB
    curve!(
        "1.2.643.7.1.2.1.1.3",
        &'static FpCtCurve<'static>,
        tc26_gost_3410_12_256_paramsetc
    ), // Tc26-Gost-3410-12-256-paramSetC
    curve!(
        "1.2.643.7.1.2.1.1.4",
        &'static FpCtCurve<'static>,
        tc26_gost_3410_12_256_paramsetd
    ), // Tc26-Gost-3410-12-256-paramSetD
    curve!(
        "1.2.643.7.1.2.1.2.1",
        &'static FpCtCurve<'static>,
        tc26_gost_3410_12_512_paramseta
    ), // Tc26-Gost-3410-12-512-paramSetA
    curve!(
        "1.2.643.7.1.2.1.2.2",
        &'static FpCtCurve<'static>,
        tc26_gost_3410_12_512_paramsetb
    ), // Tc26-Gost-3410-12-512-paramSetB
    curve!(
        "1.2.643.7.1.2.1.2.3",
        &'static FpCtCurve<'static>,
        tc26_gost_3410_12_512_paramsetc
    ), // Tc26-Gost-3410-12-512-paramSetC
    curve!(
        "1.2.156.10197.1.301.101",
        &'static FpCtCurve<'static>,
        wapip192v1
    ), // wapip192v1
    curve!(
        "1.2.156.11235.1.1.1",
        &'static FpCtCurve<'static>,
        wapi192v1
    ), // wapi192v1
    curve!(
        "1.2.156.10197.1.301",
        &'static SecPCtCurve<SM2P256V1FieldElement>,
        sm2p256v1
    ), // sm2p256v1
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.0",
        &'static F2mCtCurve,
        dstu4145_163
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.0
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.1",
        &'static F2mCtCurve,
        dstu4145_167
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.1
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.2",
        &'static F2mCtCurve,
        dstu4145_173
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.2
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.3",
        &'static F2mCtCurve,
        dstu4145_179
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.3
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.4",
        &'static F2mCtCurve,
        dstu4145_191
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.4
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.5",
        &'static F2mCtCurve,
        dstu4145_233
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.5
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.6",
        &'static F2mCtCurve,
        dstu4145_257
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.6
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.7",
        &'static F2mCtCurve,
        dstu4145_307
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.7
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.8",
        &'static F2mCtCurve,
        dstu4145_367
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.8
    curve!(
        "1.2.804.2.1.1.1.1.3.1.1.2.9",
        &'static F2mCtCurve,
        dstu4145_431
    ), // 1.2.804.2.1.1.1.1.3.1.1.2.9
];

fn secp112r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP112R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn secp112r2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP112R2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn secp128r1() -> SecPCtPoint<'static, SecP128R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP128R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP128R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp128r2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::SECP128R2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn secp160k1() -> SecPCtPoint<'static, SecP160R2FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP160R2FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp160r1() -> SecPCtPoint<'static, SecP160R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP160R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp160r2() -> SecPCtPoint<'static, SecP160R2FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP160R2FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP160R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp192k1() -> SecPCtPoint<'static, SecP192K1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP192K1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP192K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp192r1() -> SecPCtPoint<'static, SecP192R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP192R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP192R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp224k1() -> SecPCtPoint<'static, SecP224K1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP224K1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP224K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp224r1() -> SecPCtPoint<'static, SecP224R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP224R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP224R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp256k1() -> SecPCtPoint<'static, SecP256K1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP256K1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP256K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp256r1() -> SecPCtPoint<'static, SecP256R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP256R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP256R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp384r1() -> SecPCtPoint<'static, SecP384R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP384R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP384R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn secp521r1() -> SecPCtPoint<'static, SecP521R1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SecP521R1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SECP521R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect113r1() -> SecTCtPoint<'static, SecT113FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT113FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT113R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect113r2() -> SecTCtPoint<'static, SecT113FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT113FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT113R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect131r1() -> SecTCtPoint<'static, SecT131FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT131FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT131R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect131r2() -> SecTCtPoint<'static, SecT131FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT131FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT131R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect163k1() -> SecTCtPoint<'static, SecT163FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT163FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect163r1() -> SecTCtPoint<'static, SecT163FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT163FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect163r2() -> SecTCtPoint<'static, SecT163FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT163FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT163R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect193r1() -> SecTCtPoint<'static, SecT193FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT193FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT193R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect193r2() -> SecTCtPoint<'static, SecT193FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT193FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT193R2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect233k1() -> SecTCtPoint<'static, SecT233FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT233FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT233K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect233r1() -> SecTCtPoint<'static, SecT233FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT233FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT233R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect239k1() -> SecTCtPoint<'static, SecT239FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT239FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT239K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect283k1() -> SecTCtPoint<'static, SecT283FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT283FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT283K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect283r1() -> SecTCtPoint<'static, SecT283FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT283FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT283R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect409k1() -> SecTCtPoint<'static, SecT409FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT409FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT409K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect409r1() -> SecTCtPoint<'static, SecT409FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT409FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT409R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect571k1() -> SecTCtPoint<'static, SecT571FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT571FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT571K1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sect571r1() -> SecTCtPoint<'static, SecT571FieldElement> {
    static CURVE: OnceLock<SecTCtCurve<SecT571FieldElement>> = OnceLock::new();
    let named = tc_f2m_custom::named_curves::SECT571R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn prime192v2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME192V2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn prime192v3() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME192V3;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn prime239v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME239V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn prime239v2() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME239V2;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn prime239v3() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::PRIME239V3;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn c2pnb163v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB163V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2pnb163v2() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB163V2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2pnb163v3() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB163V3;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2pnb176w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB176W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb191v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB191V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb191v2() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB191V2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb191v3() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB191V3;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2pnb208w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB208W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb239v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB239V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb239v2() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB239V2;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb239v3() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB239V3;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2pnb272w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB272W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2pnb304w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB304W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb359v1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB359V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2pnb368w1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2PNB368W1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn c2tnb431r1() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::C2TNB431R1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn brainpoolp160r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP160R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp160t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP160T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp192r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP192R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp192t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP192T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp224r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP224R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp224t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP224T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp256r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP256R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp256t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP256T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp320r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP320R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp320t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP320T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp384r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP384R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp384t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP384T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp512r1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP512R1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn brainpoolp512t1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::BRAINPOOLP512T1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn frp256v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::FRP256V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn gostr3410_2001_cryptopro_a() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_A;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn gostr3410_2001_cryptopro_b() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_B;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn gostr3410_2001_cryptopro_c() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_C;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn gostr3410_2001_cryptopro_xcha() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_XCHA;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn gostr3410_2001_cryptopro_xchb() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::GOSTR3410_2001_CRYPTOPRO_XCHB;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn tc26_gost_3410_12_256_paramseta() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETA;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn tc26_gost_3410_12_256_paramsetb() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETB;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn tc26_gost_3410_12_256_paramsetc() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETC;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn tc26_gost_3410_12_256_paramsetd() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_256_PARAMSETD;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn tc26_gost_3410_12_512_paramseta() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_512_PARAMSETA;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn tc26_gost_3410_12_512_paramsetb() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_512_PARAMSETB;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn tc26_gost_3410_12_512_paramsetc() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::TC26_GOST_3410_12_512_PARAMSETC;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn wapip192v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::WAPIP192V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn wapi192v1() -> FpCtPoint<'static> {
    static FIELD: OnceLock<FpField> = OnceLock::new();
    static CURVE: OnceLock<FpCtCurve<'static>> = OnceLock::new();
    let named = tc_fp_curve::named_curves::WAPI192V1;
    let field = FIELD.get_or_init(|| named.field());
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve(field)))
}

fn dstu4145_163() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_163;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_167() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_167;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_173() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_173;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_179() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_179;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_191() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_191;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_233() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_233;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_257() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_257;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_307() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_307;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_367() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_367;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn dstu4145_431() -> F2mCtPoint<'static> {
    static CURVE: OnceLock<F2mCtCurve> = OnceLock::new();
    let named = tc_f2m_curve::named_curves::DSTU4145_431;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

fn sm2p256v1() -> SecPCtPoint<'static, SM2P256V1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SM2P256V1FieldElement>> = OnceLock::new();
    let named = tc_fp_custom::named_curves::SM2P256V1;
    named.ct_generator(CURVE.get_or_init(|| named.ct_curve()))
}

#[cfg(test)]
mod tests {
    use tc_algo::params::EcKeyGenParams;

    use super::CURVES;
    use crate::{DefaultPkcsOperatorBuilder, PkcsOperatorBuilder};

    // A curve that goes by several OIDs is written by the first of them in the table, since a key
    // does not keep the OID it was made by, as with SPKI
    #[test]
    fn a_key_of_every_curve_reads_back_to_the_same_private_key_info() {
        let oper = DefaultPkcsOperatorBuilder::default().build();
        for entry in CURVES {
            let mut key_gen = oper.x509().key_pair_generator().get_by_name("EC").unwrap();
            key_gen
                .init(&EcKeyGenParams::from_oid(entry.oid.parse().unwrap()))
                .unwrap();
            let pair = key_gen.generate().unwrap();
            let info = oper.private_key_info().encode(pair.private()).unwrap();
            let key = oper.private_key_info().decode(&info).unwrap();
            assert_eq!(
                oper.private_key_info().encode(key.as_ref()).unwrap(),
                info,
                "{}",
                entry.oid
            );
        }
    }
}
