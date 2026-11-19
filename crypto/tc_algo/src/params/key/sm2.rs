use std::sync::OnceLock;

#[cfg(feature = "sm2")]
use tc_ec_key::{EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
use tc_fp_custom::named_curves::SM2P256V1;
use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve, SecPCtPoint};

// sm2p256v1, the curve of GM/T 0003, in constant time, built once: the SM2 rows of the cipher and
// key pair generator factories take keys on it alone, and the EC key pair generator gives its keys
// on the same curve
#[cfg(feature = "sm2")]
pub(crate) type Sm2Curve = &'static SecPCtCurve<SM2P256V1FieldElement>;
// The keys of the SM2 rows, on sm2p256v1
#[cfg(feature = "sm2")]
pub type Sm2PublicKey = EcPublicKey<Sm2Curve>;
#[cfg(feature = "sm2")]
pub type Sm2PrivateKey = EcPrivateKey<Sm2Curve>;

// Its generator
pub(crate) fn sm2p256v1() -> SecPCtPoint<'static, SM2P256V1FieldElement> {
    static CURVE: OnceLock<SecPCtCurve<SM2P256V1FieldElement>> = OnceLock::new();
    SM2P256V1.ct_generator(CURVE.get_or_init(|| SM2P256V1.ct_curve()))
}

#[cfg(feature = "sm2")]
pub(crate) fn sm2_key_generation_params() -> EcKeyGenerationParams<Sm2Curve> {
    EcKeyGenerationParams::new(sm2p256v1())
}
