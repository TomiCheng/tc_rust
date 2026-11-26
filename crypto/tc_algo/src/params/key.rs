#[cfg(any(
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve"
))]
mod named_curves;
#[cfg(feature = "fp-custom")]
pub(crate) mod sm2;

#[cfg(any(
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve"
))]
pub use named_curves::*;

pub use tc_block_cipher::KeyOwned;
pub use tc_block_cipher::KeyParams;

#[cfg(feature = "gost28147")]
pub use tc_gost28147::Gost28147Params;
#[cfg(feature = "gost28147")]
pub use tc_gost28147::Gost28147ParamsOwned;
#[cfg(feature = "gost28147")]
pub use tc_gost28147::s_box as gost28147_s_box;
#[cfg(feature = "rc-cipher")]
pub use tc_rc_cipher::Rc2Params;
#[cfg(feature = "rc-cipher")]
pub use tc_rc_cipher::Rc2ParamsOwned;
#[cfg(feature = "rc-cipher")]
pub use tc_rc_cipher::Rc5Params;
#[cfg(feature = "rc-cipher")]
pub use tc_rc_cipher::Rc5ParamsOwned;
#[cfg(feature = "threefish")]
pub use tc_threefish::ThreefishParams;
#[cfg(feature = "threefish")]
pub use tc_threefish::ThreefishParamsOwned;

#[cfg(feature = "rsa")]
pub use tc_rsa::RsaKey;
#[cfg(feature = "rsa")]
pub use tc_rsa::RsaKeyParams;

#[cfg(any(
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve",
    feature = "sm2"
))]
pub use tc_ec_key::EcPrivateKey;
#[cfg(any(
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve",
    feature = "sm2"
))]
pub use tc_ec_key::EcPublicKey;

// The curves the keys are generic over, from the crates tc_algo builds them with
#[cfg(any(
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve"
))]
pub use tc_ec_core;
#[cfg(feature = "f2m-curve")]
pub use tc_f2m_curve;
#[cfg(feature = "f2m-custom")]
pub use tc_f2m_custom;
#[cfg(feature = "fp-curve")]
pub use tc_fp_curve;
#[cfg(feature = "fp-custom")]
pub use tc_fp_custom;

#[cfg(feature = "sm2")]
pub use sm2::Sm2PrivateKey;
#[cfg(feature = "sm2")]
pub use sm2::Sm2PublicKey;

#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::Ed448PrivateKey;
#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::Ed448PublicKey;
#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::Ed25519PrivateKey;
#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::Ed25519PublicKey;
#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::X448PrivateKey;
#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::X448PublicKey;
#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::X25519PrivateKey;
#[cfg(feature = "cfrg-curves")]
pub use tc_cfrg_curves::X25519PublicKey;

#[cfg(any(feature = "dh", feature = "elgamal"))]
pub use tc_dh_key::DhParameters;
#[cfg(feature = "dh")]
pub use tc_dh_key::DhPrivateKey;
#[cfg(feature = "dh")]
pub use tc_dh_key::DhPublicKey;
#[cfg(any(feature = "dh", feature = "elgamal"))]
pub use tc_dh_key::standard_groups as dh_groups;

#[cfg(feature = "dsa")]
pub use tc_dsa_signer::DsaParameters;
#[cfg(feature = "dsa")]
pub use tc_dsa_signer::DsaPrivateKey;
#[cfg(feature = "dsa")]
pub use tc_dsa_signer::DsaPublicKey;

#[cfg(feature = "gost3410")]
pub use tc_gost3410::Gost3410Parameters;
#[cfg(feature = "gost3410")]
pub use tc_gost3410::Gost3410PrivateKey;
#[cfg(feature = "gost3410")]
pub use tc_gost3410::Gost3410PublicKey;

#[cfg(feature = "elgamal")]
pub use tc_elgamal::ElGamalParameters;
#[cfg(feature = "elgamal")]
pub use tc_elgamal::ElGamalPrivateKey;
#[cfg(feature = "elgamal")]
pub use tc_elgamal::ElGamalPublicKey;

#[cfg(feature = "naccache-stern")]
pub use tc_naccache_stern::NaccacheSternPrivateKey;
#[cfg(feature = "naccache-stern")]
pub use tc_naccache_stern::NaccacheSternPublicKey;

#[cfg(feature = "ml-dsa")]
pub use tc_ml_dsa::MlDsaParameters;
#[cfg(feature = "ml-dsa")]
pub use tc_ml_dsa::MlDsaPrivateKey;
#[cfg(feature = "ml-dsa")]
pub use tc_ml_dsa::MlDsaPublicKey;

#[cfg(feature = "ml-kem")]
pub use tc_ml_kem::MlKemParameters;
#[cfg(feature = "ml-kem")]
pub use tc_ml_kem::MlKemPrivateKey;
#[cfg(feature = "ml-kem")]
pub use tc_ml_kem::MlKemPublicKey;

#[cfg(feature = "slh-dsa")]
pub use tc_slh_dsa::SlhDsaParameters;
#[cfg(feature = "slh-dsa")]
pub use tc_slh_dsa::SlhDsaPrivateKey;
#[cfg(feature = "slh-dsa")]
pub use tc_slh_dsa::SlhDsaPublicKey;
