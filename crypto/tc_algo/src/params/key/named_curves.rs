// Type aliases for the curves of the named EC curves, with the key types over them, so that a key
// pair from the EC generator can be downcast without naming the curve crate. Generated from the
// CURVES table of params/ec_curves.rs; keep the two in step.

use tc_ec_key::{EcPrivateKey, EcPublicKey};
#[cfg(feature = "f2m-curve")]
use tc_f2m_curve::F2mCtCurve;
#[cfg(feature = "f2m-custom")]
use tc_f2m_custom::{
    SecT113FieldElement, SecT131FieldElement, SecT163FieldElement, SecT193FieldElement,
    SecT233FieldElement, SecT239FieldElement, SecT283FieldElement, SecT409FieldElement,
    SecT571FieldElement, SecTCtCurve,
};
#[cfg(feature = "fp-curve")]
use tc_fp_curve::FpCtCurve;
#[cfg(feature = "fp-custom")]
use tc_fp_custom::{
    SM2P256V1FieldElement, SecP128R1FieldElement, SecP160R1FieldElement, SecP160R2FieldElement,
    SecP192K1FieldElement, SecP192R1FieldElement, SecP224K1FieldElement, SecP224R1FieldElement,
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve,
};

#[cfg(feature = "fp-curve")]
/// The curve `secp112r1`, OID `1.3.132.0.6`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Secp112r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Secp112r1`].
pub type EcSecp112r1PublicKey = EcPublicKey<Secp112r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Secp112r1`].
pub type EcSecp112r1PrivateKey = EcPrivateKey<Secp112r1>;

#[cfg(feature = "fp-curve")]
/// The curve `secp112r2`, OID `1.3.132.0.7`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Secp112r2 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Secp112r2`].
pub type EcSecp112r2PublicKey = EcPublicKey<Secp112r2>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Secp112r2`].
pub type EcSecp112r2PrivateKey = EcPrivateKey<Secp112r2>;

#[cfg(feature = "fp-custom")]
/// The curve `secp128r1`, OID `1.3.132.0.28`, as the EC key pair generator builds it.
pub type Secp128r1 = &'static SecPCtCurve<SecP128R1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp128r1`].
pub type EcSecp128r1PublicKey = EcPublicKey<Secp128r1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp128r1`].
pub type EcSecp128r1PrivateKey = EcPrivateKey<Secp128r1>;

#[cfg(feature = "fp-curve")]
/// The curve `secp128r2`, OID `1.3.132.0.29`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Secp128r2 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Secp128r2`].
pub type EcSecp128r2PublicKey = EcPublicKey<Secp128r2>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Secp128r2`].
pub type EcSecp128r2PrivateKey = EcPrivateKey<Secp128r2>;

#[cfg(feature = "fp-custom")]
/// The curve `secp160k1`, OID `1.3.132.0.9`, as the EC key pair generator builds it.
/// The same type as [`Secp160r2`]: a downcast to its keys does not tell them apart.
pub type Secp160k1 = &'static SecPCtCurve<SecP160R2FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp160k1`].
pub type EcSecp160k1PublicKey = EcPublicKey<Secp160k1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp160k1`].
pub type EcSecp160k1PrivateKey = EcPrivateKey<Secp160k1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp160r1`, OID `1.3.132.0.8`, as the EC key pair generator builds it.
pub type Secp160r1 = &'static SecPCtCurve<SecP160R1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp160r1`].
pub type EcSecp160r1PublicKey = EcPublicKey<Secp160r1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp160r1`].
pub type EcSecp160r1PrivateKey = EcPrivateKey<Secp160r1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp160r2`, OID `1.3.132.0.30`, as the EC key pair generator builds it.
/// The same type as [`Secp160k1`]: a downcast to its keys does not tell them apart.
pub type Secp160r2 = &'static SecPCtCurve<SecP160R2FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp160r2`].
pub type EcSecp160r2PublicKey = EcPublicKey<Secp160r2>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp160r2`].
pub type EcSecp160r2PrivateKey = EcPrivateKey<Secp160r2>;

#[cfg(feature = "fp-custom")]
/// The curve `secp192k1`, OID `1.3.132.0.31`, as the EC key pair generator builds it.
pub type Secp192k1 = &'static SecPCtCurve<SecP192K1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp192k1`].
pub type EcSecp192k1PublicKey = EcPublicKey<Secp192k1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp192k1`].
pub type EcSecp192k1PrivateKey = EcPrivateKey<Secp192k1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp192r1`, `prime192v1`, `P-192`, OID `1.2.840.10045.3.1.1`, as the EC key pair generator builds it.
pub type Secp192r1 = &'static SecPCtCurve<SecP192R1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp192r1`].
pub type EcSecp192r1PublicKey = EcPublicKey<Secp192r1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp192r1`].
pub type EcSecp192r1PrivateKey = EcPrivateKey<Secp192r1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp224k1`, OID `1.3.132.0.32`, as the EC key pair generator builds it.
pub type Secp224k1 = &'static SecPCtCurve<SecP224K1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp224k1`].
pub type EcSecp224k1PublicKey = EcPublicKey<Secp224k1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp224k1`].
pub type EcSecp224k1PrivateKey = EcPrivateKey<Secp224k1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp224r1`, `P-224`, OID `1.3.132.0.33`, as the EC key pair generator builds it.
pub type Secp224r1 = &'static SecPCtCurve<SecP224R1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp224r1`].
pub type EcSecp224r1PublicKey = EcPublicKey<Secp224r1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp224r1`].
pub type EcSecp224r1PrivateKey = EcPrivateKey<Secp224r1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp256k1`, OID `1.3.132.0.10`, as the EC key pair generator builds it.
pub type Secp256k1 = &'static SecPCtCurve<SecP256K1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp256k1`].
pub type EcSecp256k1PublicKey = EcPublicKey<Secp256k1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp256k1`].
pub type EcSecp256k1PrivateKey = EcPrivateKey<Secp256k1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp256r1`, `prime256v1`, `P-256`, OID `1.2.840.10045.3.1.7`, as the EC key pair generator builds it.
pub type Secp256r1 = &'static SecPCtCurve<SecP256R1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp256r1`].
pub type EcSecp256r1PublicKey = EcPublicKey<Secp256r1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp256r1`].
pub type EcSecp256r1PrivateKey = EcPrivateKey<Secp256r1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp384r1`, `P-384`, OID `1.3.132.0.34`, as the EC key pair generator builds it.
pub type Secp384r1 = &'static SecPCtCurve<SecP384R1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp384r1`].
pub type EcSecp384r1PublicKey = EcPublicKey<Secp384r1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp384r1`].
pub type EcSecp384r1PrivateKey = EcPrivateKey<Secp384r1>;

#[cfg(feature = "fp-custom")]
/// The curve `secp521r1`, `P-521`, OID `1.3.132.0.35`, as the EC key pair generator builds it.
pub type Secp521r1 = &'static SecPCtCurve<SecP521R1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Secp521r1`].
pub type EcSecp521r1PublicKey = EcPublicKey<Secp521r1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Secp521r1`].
pub type EcSecp521r1PrivateKey = EcPrivateKey<Secp521r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect113r1`, OID `1.3.132.0.4`, as the EC key pair generator builds it.
/// The same type as [`Sect113r2`]: a downcast to its keys does not tell them apart.
pub type Sect113r1 = &'static SecTCtCurve<SecT113FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect113r1`].
pub type EcSect113r1PublicKey = EcPublicKey<Sect113r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect113r1`].
pub type EcSect113r1PrivateKey = EcPrivateKey<Sect113r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect113r2`, OID `1.3.132.0.5`, as the EC key pair generator builds it.
/// The same type as [`Sect113r1`]: a downcast to its keys does not tell them apart.
pub type Sect113r2 = &'static SecTCtCurve<SecT113FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect113r2`].
pub type EcSect113r2PublicKey = EcPublicKey<Sect113r2>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect113r2`].
pub type EcSect113r2PrivateKey = EcPrivateKey<Sect113r2>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect131r1`, OID `1.3.132.0.22`, as the EC key pair generator builds it.
/// The same type as [`Sect131r2`]: a downcast to its keys does not tell them apart.
pub type Sect131r1 = &'static SecTCtCurve<SecT131FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect131r1`].
pub type EcSect131r1PublicKey = EcPublicKey<Sect131r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect131r1`].
pub type EcSect131r1PrivateKey = EcPrivateKey<Sect131r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect131r2`, OID `1.3.132.0.23`, as the EC key pair generator builds it.
/// The same type as [`Sect131r1`]: a downcast to its keys does not tell them apart.
pub type Sect131r2 = &'static SecTCtCurve<SecT131FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect131r2`].
pub type EcSect131r2PublicKey = EcPublicKey<Sect131r2>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect131r2`].
pub type EcSect131r2PrivateKey = EcPrivateKey<Sect131r2>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect163k1`, `K-163`, OID `1.3.132.0.1`, as the EC key pair generator builds it.
/// The same type as [`Sect163r1`], [`Sect163r2`]: a downcast to its keys does not tell them apart.
pub type Sect163k1 = &'static SecTCtCurve<SecT163FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect163k1`].
pub type EcSect163k1PublicKey = EcPublicKey<Sect163k1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect163k1`].
pub type EcSect163k1PrivateKey = EcPrivateKey<Sect163k1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect163r1`, OID `1.3.132.0.2`, as the EC key pair generator builds it.
/// The same type as [`Sect163k1`], [`Sect163r2`]: a downcast to its keys does not tell them apart.
pub type Sect163r1 = &'static SecTCtCurve<SecT163FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect163r1`].
pub type EcSect163r1PublicKey = EcPublicKey<Sect163r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect163r1`].
pub type EcSect163r1PrivateKey = EcPrivateKey<Sect163r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect163r2`, `B-163`, OID `1.3.132.0.15`, as the EC key pair generator builds it.
/// The same type as [`Sect163k1`], [`Sect163r1`]: a downcast to its keys does not tell them apart.
pub type Sect163r2 = &'static SecTCtCurve<SecT163FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect163r2`].
pub type EcSect163r2PublicKey = EcPublicKey<Sect163r2>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect163r2`].
pub type EcSect163r2PrivateKey = EcPrivateKey<Sect163r2>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect193r1`, OID `1.3.132.0.24`, as the EC key pair generator builds it.
/// The same type as [`Sect193r2`]: a downcast to its keys does not tell them apart.
pub type Sect193r1 = &'static SecTCtCurve<SecT193FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect193r1`].
pub type EcSect193r1PublicKey = EcPublicKey<Sect193r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect193r1`].
pub type EcSect193r1PrivateKey = EcPrivateKey<Sect193r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect193r2`, OID `1.3.132.0.25`, as the EC key pair generator builds it.
/// The same type as [`Sect193r1`]: a downcast to its keys does not tell them apart.
pub type Sect193r2 = &'static SecTCtCurve<SecT193FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect193r2`].
pub type EcSect193r2PublicKey = EcPublicKey<Sect193r2>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect193r2`].
pub type EcSect193r2PrivateKey = EcPrivateKey<Sect193r2>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect233k1`, `K-233`, OID `1.3.132.0.26`, as the EC key pair generator builds it.
/// The same type as [`Sect233r1`]: a downcast to its keys does not tell them apart.
pub type Sect233k1 = &'static SecTCtCurve<SecT233FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect233k1`].
pub type EcSect233k1PublicKey = EcPublicKey<Sect233k1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect233k1`].
pub type EcSect233k1PrivateKey = EcPrivateKey<Sect233k1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect233r1`, `B-233`, OID `1.3.132.0.27`, as the EC key pair generator builds it.
/// The same type as [`Sect233k1`]: a downcast to its keys does not tell them apart.
pub type Sect233r1 = &'static SecTCtCurve<SecT233FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect233r1`].
pub type EcSect233r1PublicKey = EcPublicKey<Sect233r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect233r1`].
pub type EcSect233r1PrivateKey = EcPrivateKey<Sect233r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect239k1`, OID `1.3.132.0.3`, as the EC key pair generator builds it.
pub type Sect239k1 = &'static SecTCtCurve<SecT239FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect239k1`].
pub type EcSect239k1PublicKey = EcPublicKey<Sect239k1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect239k1`].
pub type EcSect239k1PrivateKey = EcPrivateKey<Sect239k1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect283k1`, `K-283`, OID `1.3.132.0.16`, as the EC key pair generator builds it.
/// The same type as [`Sect283r1`]: a downcast to its keys does not tell them apart.
pub type Sect283k1 = &'static SecTCtCurve<SecT283FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect283k1`].
pub type EcSect283k1PublicKey = EcPublicKey<Sect283k1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect283k1`].
pub type EcSect283k1PrivateKey = EcPrivateKey<Sect283k1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect283r1`, `B-283`, OID `1.3.132.0.17`, as the EC key pair generator builds it.
/// The same type as [`Sect283k1`]: a downcast to its keys does not tell them apart.
pub type Sect283r1 = &'static SecTCtCurve<SecT283FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect283r1`].
pub type EcSect283r1PublicKey = EcPublicKey<Sect283r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect283r1`].
pub type EcSect283r1PrivateKey = EcPrivateKey<Sect283r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect409k1`, `K-409`, OID `1.3.132.0.36`, as the EC key pair generator builds it.
/// The same type as [`Sect409r1`]: a downcast to its keys does not tell them apart.
pub type Sect409k1 = &'static SecTCtCurve<SecT409FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect409k1`].
pub type EcSect409k1PublicKey = EcPublicKey<Sect409k1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect409k1`].
pub type EcSect409k1PrivateKey = EcPrivateKey<Sect409k1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect409r1`, `B-409`, OID `1.3.132.0.37`, as the EC key pair generator builds it.
/// The same type as [`Sect409k1`]: a downcast to its keys does not tell them apart.
pub type Sect409r1 = &'static SecTCtCurve<SecT409FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect409r1`].
pub type EcSect409r1PublicKey = EcPublicKey<Sect409r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect409r1`].
pub type EcSect409r1PrivateKey = EcPrivateKey<Sect409r1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect571k1`, `K-571`, OID `1.3.132.0.38`, as the EC key pair generator builds it.
/// The same type as [`Sect571r1`]: a downcast to its keys does not tell them apart.
pub type Sect571k1 = &'static SecTCtCurve<SecT571FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect571k1`].
pub type EcSect571k1PublicKey = EcPublicKey<Sect571k1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect571k1`].
pub type EcSect571k1PrivateKey = EcPrivateKey<Sect571k1>;

#[cfg(feature = "f2m-custom")]
/// The curve `sect571r1`, `B-571`, OID `1.3.132.0.39`, as the EC key pair generator builds it.
/// The same type as [`Sect571k1`]: a downcast to its keys does not tell them apart.
pub type Sect571r1 = &'static SecTCtCurve<SecT571FieldElement>;
#[cfg(feature = "f2m-custom")]
/// A public key on [`Sect571r1`].
pub type EcSect571r1PublicKey = EcPublicKey<Sect571r1>;
#[cfg(feature = "f2m-custom")]
/// A private key on [`Sect571r1`].
pub type EcSect571r1PrivateKey = EcPrivateKey<Sect571r1>;

#[cfg(feature = "fp-curve")]
/// The curve `prime192v2`, OID `1.2.840.10045.3.1.2`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Prime192v2 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Prime192v2`].
pub type EcPrime192v2PublicKey = EcPublicKey<Prime192v2>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Prime192v2`].
pub type EcPrime192v2PrivateKey = EcPrivateKey<Prime192v2>;

#[cfg(feature = "fp-curve")]
/// The curve `prime192v3`, OID `1.2.840.10045.3.1.3`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Prime192v3 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Prime192v3`].
pub type EcPrime192v3PublicKey = EcPublicKey<Prime192v3>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Prime192v3`].
pub type EcPrime192v3PrivateKey = EcPrivateKey<Prime192v3>;

#[cfg(feature = "fp-curve")]
/// The curve `prime239v1`, OID `1.2.840.10045.3.1.4`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Prime239v1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Prime239v1`].
pub type EcPrime239v1PublicKey = EcPublicKey<Prime239v1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Prime239v1`].
pub type EcPrime239v1PrivateKey = EcPrivateKey<Prime239v1>;

#[cfg(feature = "fp-curve")]
/// The curve `prime239v2`, OID `1.2.840.10045.3.1.5`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Prime239v2 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Prime239v2`].
pub type EcPrime239v2PublicKey = EcPublicKey<Prime239v2>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Prime239v2`].
pub type EcPrime239v2PrivateKey = EcPrivateKey<Prime239v2>;

#[cfg(feature = "fp-curve")]
/// The curve `prime239v3`, OID `1.2.840.10045.3.1.6`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Prime239v3 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Prime239v3`].
pub type EcPrime239v3PublicKey = EcPublicKey<Prime239v3>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Prime239v3`].
pub type EcPrime239v3PrivateKey = EcPrivateKey<Prime239v3>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb163v1`, OID `1.2.840.10045.3.0.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb163v1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb163v1`].
pub type EcC2pnb163v1PublicKey = EcPublicKey<C2pnb163v1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb163v1`].
pub type EcC2pnb163v1PrivateKey = EcPrivateKey<C2pnb163v1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb163v2`, OID `1.2.840.10045.3.0.2`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb163v2 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb163v2`].
pub type EcC2pnb163v2PublicKey = EcPublicKey<C2pnb163v2>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb163v2`].
pub type EcC2pnb163v2PrivateKey = EcPrivateKey<C2pnb163v2>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb163v3`, OID `1.2.840.10045.3.0.3`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb163v3 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb163v3`].
pub type EcC2pnb163v3PublicKey = EcPublicKey<C2pnb163v3>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb163v3`].
pub type EcC2pnb163v3PrivateKey = EcPrivateKey<C2pnb163v3>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb176w1`, OID `1.2.840.10045.3.0.4`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb176w1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb176w1`].
pub type EcC2pnb176w1PublicKey = EcPublicKey<C2pnb176w1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb176w1`].
pub type EcC2pnb176w1PrivateKey = EcPrivateKey<C2pnb176w1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb191v1`, OID `1.2.840.10045.3.0.5`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb191v1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb191v1`].
pub type EcC2tnb191v1PublicKey = EcPublicKey<C2tnb191v1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb191v1`].
pub type EcC2tnb191v1PrivateKey = EcPrivateKey<C2tnb191v1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb191v2`, OID `1.2.840.10045.3.0.6`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb191v2 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb191v2`].
pub type EcC2tnb191v2PublicKey = EcPublicKey<C2tnb191v2>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb191v2`].
pub type EcC2tnb191v2PrivateKey = EcPrivateKey<C2tnb191v2>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb191v3`, OID `1.2.840.10045.3.0.7`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb191v3 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb191v3`].
pub type EcC2tnb191v3PublicKey = EcPublicKey<C2tnb191v3>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb191v3`].
pub type EcC2tnb191v3PrivateKey = EcPrivateKey<C2tnb191v3>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb208w1`, OID `1.2.840.10045.3.0.10`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb208w1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb208w1`].
pub type EcC2pnb208w1PublicKey = EcPublicKey<C2pnb208w1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb208w1`].
pub type EcC2pnb208w1PrivateKey = EcPrivateKey<C2pnb208w1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb239v1`, OID `1.2.840.10045.3.0.11`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb239v1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb239v1`].
pub type EcC2tnb239v1PublicKey = EcPublicKey<C2tnb239v1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb239v1`].
pub type EcC2tnb239v1PrivateKey = EcPrivateKey<C2tnb239v1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb239v2`, OID `1.2.840.10045.3.0.12`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb239v2 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb239v2`].
pub type EcC2tnb239v2PublicKey = EcPublicKey<C2tnb239v2>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb239v2`].
pub type EcC2tnb239v2PrivateKey = EcPrivateKey<C2tnb239v2>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb239v3`, OID `1.2.840.10045.3.0.13`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb239v3 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb239v3`].
pub type EcC2tnb239v3PublicKey = EcPublicKey<C2tnb239v3>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb239v3`].
pub type EcC2tnb239v3PrivateKey = EcPrivateKey<C2tnb239v3>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb272w1`, OID `1.2.840.10045.3.0.16`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb272w1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb272w1`].
pub type EcC2pnb272w1PublicKey = EcPublicKey<C2pnb272w1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb272w1`].
pub type EcC2pnb272w1PrivateKey = EcPrivateKey<C2pnb272w1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb304w1`, OID `1.2.840.10045.3.0.17`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb304w1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb304w1`].
pub type EcC2pnb304w1PublicKey = EcPublicKey<C2pnb304w1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb304w1`].
pub type EcC2pnb304w1PrivateKey = EcPrivateKey<C2pnb304w1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb359v1`, OID `1.2.840.10045.3.0.18`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb359v1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb359v1`].
pub type EcC2tnb359v1PublicKey = EcPublicKey<C2tnb359v1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb359v1`].
pub type EcC2tnb359v1PrivateKey = EcPrivateKey<C2tnb359v1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2pnb368w1`, OID `1.2.840.10045.3.0.19`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2pnb368w1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2pnb368w1`].
pub type EcC2pnb368w1PublicKey = EcPublicKey<C2pnb368w1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2pnb368w1`].
pub type EcC2pnb368w1PrivateKey = EcPrivateKey<C2pnb368w1>;

#[cfg(feature = "f2m-curve")]
/// The curve `c2tnb431r1`, OID `1.2.840.10045.3.0.20`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type C2tnb431r1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`C2tnb431r1`].
pub type EcC2tnb431r1PublicKey = EcPublicKey<C2tnb431r1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`C2tnb431r1`].
pub type EcC2tnb431r1PrivateKey = EcPrivateKey<C2tnb431r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP160r1`, OID `1.3.36.3.3.2.8.1.1.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP160r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP160r1`].
pub type EcBrainpoolP160r1PublicKey = EcPublicKey<BrainpoolP160r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP160r1`].
pub type EcBrainpoolP160r1PrivateKey = EcPrivateKey<BrainpoolP160r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP160t1`, OID `1.3.36.3.3.2.8.1.1.2`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP160t1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP160t1`].
pub type EcBrainpoolP160t1PublicKey = EcPublicKey<BrainpoolP160t1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP160t1`].
pub type EcBrainpoolP160t1PrivateKey = EcPrivateKey<BrainpoolP160t1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP192r1`, OID `1.3.36.3.3.2.8.1.1.3`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP192r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP192r1`].
pub type EcBrainpoolP192r1PublicKey = EcPublicKey<BrainpoolP192r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP192r1`].
pub type EcBrainpoolP192r1PrivateKey = EcPrivateKey<BrainpoolP192r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP192t1`, OID `1.3.36.3.3.2.8.1.1.4`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP192t1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP192t1`].
pub type EcBrainpoolP192t1PublicKey = EcPublicKey<BrainpoolP192t1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP192t1`].
pub type EcBrainpoolP192t1PrivateKey = EcPrivateKey<BrainpoolP192t1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP224r1`, OID `1.3.36.3.3.2.8.1.1.5`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP224r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP224r1`].
pub type EcBrainpoolP224r1PublicKey = EcPublicKey<BrainpoolP224r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP224r1`].
pub type EcBrainpoolP224r1PrivateKey = EcPrivateKey<BrainpoolP224r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP224t1`, OID `1.3.36.3.3.2.8.1.1.6`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP224t1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP224t1`].
pub type EcBrainpoolP224t1PublicKey = EcPublicKey<BrainpoolP224t1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP224t1`].
pub type EcBrainpoolP224t1PrivateKey = EcPrivateKey<BrainpoolP224t1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP256r1`, OID `1.3.36.3.3.2.8.1.1.7`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP256r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP256r1`].
pub type EcBrainpoolP256r1PublicKey = EcPublicKey<BrainpoolP256r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP256r1`].
pub type EcBrainpoolP256r1PrivateKey = EcPrivateKey<BrainpoolP256r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP256t1`, OID `1.3.36.3.3.2.8.1.1.8`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP256t1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP256t1`].
pub type EcBrainpoolP256t1PublicKey = EcPublicKey<BrainpoolP256t1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP256t1`].
pub type EcBrainpoolP256t1PrivateKey = EcPrivateKey<BrainpoolP256t1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP320r1`, OID `1.3.36.3.3.2.8.1.1.9`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP320r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP320r1`].
pub type EcBrainpoolP320r1PublicKey = EcPublicKey<BrainpoolP320r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP320r1`].
pub type EcBrainpoolP320r1PrivateKey = EcPrivateKey<BrainpoolP320r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP320t1`, OID `1.3.36.3.3.2.8.1.1.10`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP320t1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP320t1`].
pub type EcBrainpoolP320t1PublicKey = EcPublicKey<BrainpoolP320t1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP320t1`].
pub type EcBrainpoolP320t1PrivateKey = EcPrivateKey<BrainpoolP320t1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP384r1`, OID `1.3.36.3.3.2.8.1.1.11`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP384r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP384r1`].
pub type EcBrainpoolP384r1PublicKey = EcPublicKey<BrainpoolP384r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP384r1`].
pub type EcBrainpoolP384r1PrivateKey = EcPrivateKey<BrainpoolP384r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP384t1`, OID `1.3.36.3.3.2.8.1.1.12`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP384t1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP384t1`].
pub type EcBrainpoolP384t1PublicKey = EcPublicKey<BrainpoolP384t1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP384t1`].
pub type EcBrainpoolP384t1PrivateKey = EcPrivateKey<BrainpoolP384t1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP512r1`, OID `1.3.36.3.3.2.8.1.1.13`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP512r1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP512r1`].
pub type EcBrainpoolP512r1PublicKey = EcPublicKey<BrainpoolP512r1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP512r1`].
pub type EcBrainpoolP512r1PrivateKey = EcPrivateKey<BrainpoolP512r1>;

#[cfg(feature = "fp-curve")]
/// The curve `brainpoolP512t1`, OID `1.3.36.3.3.2.8.1.1.14`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type BrainpoolP512t1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`BrainpoolP512t1`].
pub type EcBrainpoolP512t1PublicKey = EcPublicKey<BrainpoolP512t1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`BrainpoolP512t1`].
pub type EcBrainpoolP512t1PrivateKey = EcPrivateKey<BrainpoolP512t1>;

#[cfg(feature = "fp-curve")]
/// The curve `FRP256v1`, OID `1.2.250.1.223.101.256.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type FRP256v1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`FRP256v1`].
pub type EcFRP256v1PublicKey = EcPublicKey<FRP256v1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`FRP256v1`].
pub type EcFRP256v1PrivateKey = EcPrivateKey<FRP256v1>;

#[cfg(feature = "fp-curve")]
/// The curve `GostR3410-2001-CryptoPro-A`, OID `1.2.643.2.2.35.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type GostR34102001CryptoProA = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`GostR34102001CryptoProA`].
pub type EcGostR34102001CryptoProAPublicKey = EcPublicKey<GostR34102001CryptoProA>;
#[cfg(feature = "fp-curve")]
/// A private key on [`GostR34102001CryptoProA`].
pub type EcGostR34102001CryptoProAPrivateKey = EcPrivateKey<GostR34102001CryptoProA>;

#[cfg(feature = "fp-curve")]
/// The curve `GostR3410-2001-CryptoPro-B`, OID `1.2.643.2.2.35.2`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type GostR34102001CryptoProB = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`GostR34102001CryptoProB`].
pub type EcGostR34102001CryptoProBPublicKey = EcPublicKey<GostR34102001CryptoProB>;
#[cfg(feature = "fp-curve")]
/// A private key on [`GostR34102001CryptoProB`].
pub type EcGostR34102001CryptoProBPrivateKey = EcPrivateKey<GostR34102001CryptoProB>;

#[cfg(feature = "fp-curve")]
/// The curve `GostR3410-2001-CryptoPro-C`, OID `1.2.643.2.2.35.3`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type GostR34102001CryptoProC = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`GostR34102001CryptoProC`].
pub type EcGostR34102001CryptoProCPublicKey = EcPublicKey<GostR34102001CryptoProC>;
#[cfg(feature = "fp-curve")]
/// A private key on [`GostR34102001CryptoProC`].
pub type EcGostR34102001CryptoProCPrivateKey = EcPrivateKey<GostR34102001CryptoProC>;

#[cfg(feature = "fp-curve")]
/// The curve `GostR3410-2001-CryptoPro-XchA`, OID `1.2.643.2.2.36.0`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type GostR34102001CryptoProXchA = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`GostR34102001CryptoProXchA`].
pub type EcGostR34102001CryptoProXchAPublicKey = EcPublicKey<GostR34102001CryptoProXchA>;
#[cfg(feature = "fp-curve")]
/// A private key on [`GostR34102001CryptoProXchA`].
pub type EcGostR34102001CryptoProXchAPrivateKey = EcPrivateKey<GostR34102001CryptoProXchA>;

#[cfg(feature = "fp-curve")]
/// The curve `GostR3410-2001-CryptoPro-XchB`, OID `1.2.643.2.2.36.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type GostR34102001CryptoProXchB = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`GostR34102001CryptoProXchB`].
pub type EcGostR34102001CryptoProXchBPublicKey = EcPublicKey<GostR34102001CryptoProXchB>;
#[cfg(feature = "fp-curve")]
/// A private key on [`GostR34102001CryptoProXchB`].
pub type EcGostR34102001CryptoProXchBPrivateKey = EcPrivateKey<GostR34102001CryptoProXchB>;

#[cfg(feature = "fp-curve")]
/// The curve `Tc26-Gost-3410-12-256-paramSetA`, OID `1.2.643.7.1.2.1.1.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Tc26Gost341012256ParamSetA = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Tc26Gost341012256ParamSetA`].
pub type EcTc26Gost341012256ParamSetAPublicKey = EcPublicKey<Tc26Gost341012256ParamSetA>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Tc26Gost341012256ParamSetA`].
pub type EcTc26Gost341012256ParamSetAPrivateKey = EcPrivateKey<Tc26Gost341012256ParamSetA>;

#[cfg(feature = "fp-curve")]
/// The curve `Tc26-Gost-3410-12-256-paramSetB`, OID `1.2.643.7.1.2.1.1.2`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Tc26Gost341012256ParamSetB = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Tc26Gost341012256ParamSetB`].
pub type EcTc26Gost341012256ParamSetBPublicKey = EcPublicKey<Tc26Gost341012256ParamSetB>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Tc26Gost341012256ParamSetB`].
pub type EcTc26Gost341012256ParamSetBPrivateKey = EcPrivateKey<Tc26Gost341012256ParamSetB>;

#[cfg(feature = "fp-curve")]
/// The curve `Tc26-Gost-3410-12-256-paramSetC`, OID `1.2.643.7.1.2.1.1.3`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Tc26Gost341012256ParamSetC = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Tc26Gost341012256ParamSetC`].
pub type EcTc26Gost341012256ParamSetCPublicKey = EcPublicKey<Tc26Gost341012256ParamSetC>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Tc26Gost341012256ParamSetC`].
pub type EcTc26Gost341012256ParamSetCPrivateKey = EcPrivateKey<Tc26Gost341012256ParamSetC>;

#[cfg(feature = "fp-curve")]
/// The curve `Tc26-Gost-3410-12-256-paramSetD`, OID `1.2.643.7.1.2.1.1.4`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Tc26Gost341012256ParamSetD = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Tc26Gost341012256ParamSetD`].
pub type EcTc26Gost341012256ParamSetDPublicKey = EcPublicKey<Tc26Gost341012256ParamSetD>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Tc26Gost341012256ParamSetD`].
pub type EcTc26Gost341012256ParamSetDPrivateKey = EcPrivateKey<Tc26Gost341012256ParamSetD>;

#[cfg(feature = "fp-curve")]
/// The curve `Tc26-Gost-3410-12-512-paramSetA`, OID `1.2.643.7.1.2.1.2.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Tc26Gost341012512ParamSetA = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Tc26Gost341012512ParamSetA`].
pub type EcTc26Gost341012512ParamSetAPublicKey = EcPublicKey<Tc26Gost341012512ParamSetA>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Tc26Gost341012512ParamSetA`].
pub type EcTc26Gost341012512ParamSetAPrivateKey = EcPrivateKey<Tc26Gost341012512ParamSetA>;

#[cfg(feature = "fp-curve")]
/// The curve `Tc26-Gost-3410-12-512-paramSetB`, OID `1.2.643.7.1.2.1.2.2`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Tc26Gost341012512ParamSetB = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Tc26Gost341012512ParamSetB`].
pub type EcTc26Gost341012512ParamSetBPublicKey = EcPublicKey<Tc26Gost341012512ParamSetB>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Tc26Gost341012512ParamSetB`].
pub type EcTc26Gost341012512ParamSetBPrivateKey = EcPrivateKey<Tc26Gost341012512ParamSetB>;

#[cfg(feature = "fp-curve")]
/// The curve `Tc26-Gost-3410-12-512-paramSetC`, OID `1.2.643.7.1.2.1.2.3`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Tc26Gost341012512ParamSetC = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Tc26Gost341012512ParamSetC`].
pub type EcTc26Gost341012512ParamSetCPublicKey = EcPublicKey<Tc26Gost341012512ParamSetC>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Tc26Gost341012512ParamSetC`].
pub type EcTc26Gost341012512ParamSetCPrivateKey = EcPrivateKey<Tc26Gost341012512ParamSetC>;

#[cfg(feature = "fp-curve")]
/// The curve `wapip192v1`, OID `1.2.156.10197.1.301.101`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Wapip192v1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Wapip192v1`].
pub type EcWapip192v1PublicKey = EcPublicKey<Wapip192v1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Wapip192v1`].
pub type EcWapip192v1PrivateKey = EcPrivateKey<Wapip192v1>;

#[cfg(feature = "fp-curve")]
/// The curve `wapi192v1`, OID `1.2.156.11235.1.1.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_fp_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Wapi192v1 = &'static FpCtCurve<'static>;
#[cfg(feature = "fp-curve")]
/// A public key on [`Wapi192v1`].
pub type EcWapi192v1PublicKey = EcPublicKey<Wapi192v1>;
#[cfg(feature = "fp-curve")]
/// A private key on [`Wapi192v1`].
pub type EcWapi192v1PrivateKey = EcPrivateKey<Wapi192v1>;

#[cfg(feature = "fp-custom")]
/// The curve `sm2p256v1`, OID `1.2.156.10197.1.301`, as the EC key pair generator builds it.
pub type Sm2p256v1 = &'static SecPCtCurve<SM2P256V1FieldElement>;
#[cfg(feature = "fp-custom")]
/// A public key on [`Sm2p256v1`].
pub type EcSm2p256v1PublicKey = EcPublicKey<Sm2p256v1>;
#[cfg(feature = "fp-custom")]
/// A private key on [`Sm2p256v1`].
pub type EcSm2p256v1PrivateKey = EcPrivateKey<Sm2p256v1>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.0`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve0 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve0`].
pub type EcDstu4145Curve0PublicKey = EcPublicKey<Dstu4145Curve0>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve0`].
pub type EcDstu4145Curve0PrivateKey = EcPrivateKey<Dstu4145Curve0>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.1`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve1 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve1`].
pub type EcDstu4145Curve1PublicKey = EcPublicKey<Dstu4145Curve1>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve1`].
pub type EcDstu4145Curve1PrivateKey = EcPrivateKey<Dstu4145Curve1>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.2`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve2 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve2`].
pub type EcDstu4145Curve2PublicKey = EcPublicKey<Dstu4145Curve2>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve2`].
pub type EcDstu4145Curve2PrivateKey = EcPrivateKey<Dstu4145Curve2>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.3`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve3 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve3`].
pub type EcDstu4145Curve3PublicKey = EcPublicKey<Dstu4145Curve3>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve3`].
pub type EcDstu4145Curve3PrivateKey = EcPrivateKey<Dstu4145Curve3>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.4`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve4 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve4`].
pub type EcDstu4145Curve4PublicKey = EcPublicKey<Dstu4145Curve4>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve4`].
pub type EcDstu4145Curve4PrivateKey = EcPrivateKey<Dstu4145Curve4>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.5`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve5 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve5`].
pub type EcDstu4145Curve5PublicKey = EcPublicKey<Dstu4145Curve5>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve5`].
pub type EcDstu4145Curve5PrivateKey = EcPrivateKey<Dstu4145Curve5>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.6`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve6 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve6`].
pub type EcDstu4145Curve6PublicKey = EcPublicKey<Dstu4145Curve6>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve6`].
pub type EcDstu4145Curve6PrivateKey = EcPrivateKey<Dstu4145Curve6>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.7`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve7 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve7`].
pub type EcDstu4145Curve7PublicKey = EcPublicKey<Dstu4145Curve7>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve7`].
pub type EcDstu4145Curve7PrivateKey = EcPrivateKey<Dstu4145Curve7>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.8`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve8 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve8`].
pub type EcDstu4145Curve8PublicKey = EcPublicKey<Dstu4145Curve8>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve8`].
pub type EcDstu4145Curve8PrivateKey = EcPrivateKey<Dstu4145Curve8>;

#[cfg(feature = "f2m-curve")]
/// The curve no name, OID `1.2.804.2.1.1.1.1.3.1.1.2.9`, as the EC key pair generator builds it.
/// It is the generic curve of `tc_f2m_curve`, the same type as every other curve built on it,
/// so a downcast to its keys does not tell the curves apart.
pub type Dstu4145Curve9 = &'static F2mCtCurve;
#[cfg(feature = "f2m-curve")]
/// A public key on [`Dstu4145Curve9`].
pub type EcDstu4145Curve9PublicKey = EcPublicKey<Dstu4145Curve9>;
#[cfg(feature = "f2m-curve")]
/// A private key on [`Dstu4145Curve9`].
pub type EcDstu4145Curve9PrivateKey = EcPrivateKey<Dstu4145Curve9>;
