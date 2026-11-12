use rand_core::CryptoRng;
use tc_asn1::NamedOid;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator, EcPrivateKey, EcPublicKey};

use crate::generate::KeyGenParams;
use crate::generate::key_pair::{KeyPair, KeyPairGeneratorEntry};
use crate::params::ec_curves::{self, with_ec_curves};
use crate::params::{AnyEcPrivateKey, AnyEcPublicKey, AnyPrivateKey, AnyPublicKey, EcCurve};
use crate::{AlgoError, ErrorKind};

// The curve Bouncy Castle's ECKeyPairGenerator takes for a size alone. Its 239 bits name
// prime239v1, which this crate does not have, and its 192 bits P-192, one of the small curves
fn curve_of_size(bits: usize) -> Option<EcCurve> {
    match bits {
        #[cfg(feature = "ec-small-curves")]
        192 => Some(EcCurve::Secp192r1),
        224 => Some(EcCurve::Secp224r1),
        256 => Some(EcCurve::Secp256r1),
        384 => Some(EcCurve::Secp384r1),
        521 => Some(EcCurve::Secp521r1),
        _ => None,
    }
}

fn curve(params: &KeyGenParams) -> Result<EcCurve, AlgoError> {
    let curve = match params {
        KeyGenParams::Ec { curve } => Some(*curve),
        KeyGenParams::Strength { bits } => curve_of_size(*bits),
        #[allow(unreachable_patterns, reason = "every other variant may be off")]
        _ => None,
    };
    curve.ok_or(AlgoError::new(ErrorKind::InvalidKeyGenParams))
}

fn check_params(params: &KeyGenParams) -> Result<(), AlgoError> {
    curve(params).map(|_| ())
}

fn generate(params: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<KeyPair, AlgoError> {
    generate_on(curve(params)?, rng)
}

macro_rules! generate_on {
    ($($(#[$cfg:meta])* $curve:ident => $generator:ident,)*) => {
        fn generate_on(curve: EcCurve, rng: &mut dyn CryptoRng) -> Result<KeyPair, AlgoError> {
            match curve {
                $(
                    $(#[$cfg])*
                    EcCurve::$curve => key_pair(
                        ec_curves::$generator(),
                        rng,
                        AnyEcPublicKey::$curve,
                        AnyEcPrivateKey::$curve,
                    ),
                )*
            }
        }
    };
}

with_ec_curves!(generate_on);

fn key_pair<C: Curve<Scalar = PaddedBigUint>>(
    g: C::Point,
    rng: &mut dyn CryptoRng,
    public: fn(Box<EcPublicKey<C>>) -> AnyEcPublicKey,
    private: fn(Box<EcPrivateKey<C>>) -> AnyEcPrivateKey,
) -> Result<KeyPair, AlgoError> {
    // A named curve always passes tc_ec_key's checks, so these cannot fail in practice
    let invalid = |error| AlgoError::with_source(ErrorKind::InvalidKeyGenParams, error);
    let mut generator = EcKeyPairGenerator::<C>::new();
    generator
        .init(EcKeyGenerationParams::new(g, rng))
        .map_err(invalid)?;
    let (q, d) = generator.generate_key_pair().map_err(invalid)?;
    Ok(KeyPair {
        public: AnyPublicKey::Ec(public(Box::new(q))),
        private: AnyPrivateKey::Ec(private(Box::new(d))),
    })
}

// X9.63 and SEC 1 name the ECDH and ECMQV schemes with a KDF; Bouncy Castle finds this generator
// by them
macro_rules! x963_scheme {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x2b, 0x81, 0x05, 0x10, 0x86, 0x48, 0x3f, 0x00, $arc],
            $dotted,
            $name,
        )
    };
}

macro_rules! secg_scheme {
    ($branch:literal, $arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(&[0x2b, 0x81, 0x04, 0x01, $branch, $arc], $dotted, $name)
    };
}

// Bouncy Castle's ECKeyPairGenerator under the names of its EC, ECDH, ECDHC and ECMQV rows, with
// ECIES as the alias of ECDH. The keys are the same for all of them, as they carry no algorithm
// name here, so one row serves. The OIDs are those of the EC and ECMQV rows. There is no default
// curve, so init is required
pub(super) const EC: KeyPairGeneratorEntry = KeyPairGeneratorEntry::new(
    &["EC", "ECDH", "ECIES", "ECDHC", "ECMQV"],
    &[
        x963_scheme!(
            0x02,
            "1.3.133.16.840.63.0.2",
            "dhSinglePass-stdDH-sha1kdf-scheme"
        ),
        secg_scheme!(
            0x0b,
            0x00,
            "1.3.132.1.11.0",
            "dhSinglePass-stdDH-sha224kdf-scheme"
        ),
        secg_scheme!(
            0x0b,
            0x01,
            "1.3.132.1.11.1",
            "dhSinglePass-stdDH-sha256kdf-scheme"
        ),
        secg_scheme!(
            0x0b,
            0x02,
            "1.3.132.1.11.2",
            "dhSinglePass-stdDH-sha384kdf-scheme"
        ),
        secg_scheme!(
            0x0b,
            0x03,
            "1.3.132.1.11.3",
            "dhSinglePass-stdDH-sha512kdf-scheme"
        ),
        x963_scheme!(
            0x03,
            "1.3.133.16.840.63.0.3",
            "dhSinglePass-cofactorDH-sha1kdf-scheme"
        ),
        secg_scheme!(
            0x0e,
            0x00,
            "1.3.132.1.14.0",
            "dhSinglePass-cofactorDH-sha224kdf-scheme"
        ),
        secg_scheme!(
            0x0e,
            0x01,
            "1.3.132.1.14.1",
            "dhSinglePass-cofactorDH-sha256kdf-scheme"
        ),
        secg_scheme!(
            0x0e,
            0x02,
            "1.3.132.1.14.2",
            "dhSinglePass-cofactorDH-sha384kdf-scheme"
        ),
        secg_scheme!(
            0x0e,
            0x03,
            "1.3.132.1.14.3",
            "dhSinglePass-cofactorDH-sha512kdf-scheme"
        ),
        x963_scheme!(
            0x10,
            "1.3.133.16.840.63.0.16",
            "mqvSinglePass-sha1kdf-scheme"
        ),
        secg_scheme!(
            0x0f,
            0x00,
            "1.3.132.1.15.0",
            "mqvSinglePass-sha224kdf-scheme"
        ),
        secg_scheme!(
            0x0f,
            0x01,
            "1.3.132.1.15.1",
            "mqvSinglePass-sha256kdf-scheme"
        ),
        secg_scheme!(
            0x0f,
            0x02,
            "1.3.132.1.15.2",
            "mqvSinglePass-sha384kdf-scheme"
        ),
        secg_scheme!(
            0x0f,
            0x03,
            "1.3.132.1.15.3",
            "mqvSinglePass-sha512kdf-scheme"
        ),
    ],
    None,
    check_params,
    generate,
);
