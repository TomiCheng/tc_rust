use std::sync::LazyLock;

use tc_ec_key::{EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
use tc_fp_custom::named_curves::SM2P256V1;
use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve};

// sm2p256v1, the curve of GM/T 0003, in constant time, built once: the SM2 rows of the cipher and
// key pair generator factories take keys on it alone
pub(crate) type Sm2Curve = &'static SecPCtCurve<SM2P256V1FieldElement>;
pub(crate) type Sm2PublicKey = EcPublicKey<Sm2Curve>;
pub(crate) type Sm2PrivateKey = EcPrivateKey<Sm2Curve>;

static CURVE: LazyLock<SecPCtCurve<SM2P256V1FieldElement>> = LazyLock::new(|| SM2P256V1.ct_curve());

// Its generator, for EcKeyPairGenerator
pub(crate) fn sm2_key_generation_params() -> EcKeyGenerationParams<Sm2Curve> {
    EcKeyGenerationParams::new(SM2P256V1.ct_generator(&CURVE))
}
