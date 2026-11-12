use core::fmt;

// One variant per algorithm, each holding the key type of the crate that implements it
#[derive(Clone)]
#[non_exhaustive]
pub enum AnyPublicKey {
    // A key whose exponent is e
    #[cfg(feature = "rsa")]
    Rsa(tc_rsa::RsaKey),
    #[cfg(feature = "ec")]
    Ec(super::AnyEcPublicKey),
    #[cfg(feature = "x25519")]
    X25519(tc_cfrg_curves::X25519PublicKey),
    #[cfg(feature = "x448")]
    X448(tc_cfrg_curves::X448PublicKey),
    #[cfg(feature = "ed25519")]
    Ed25519(tc_cfrg_curves::Ed25519PublicKey),
    #[cfg(feature = "ed448")]
    Ed448(tc_cfrg_curves::Ed448PublicKey),
    #[cfg(feature = "dh")]
    Dh(tc_dh_key::DhPublicKey),
    #[cfg(feature = "dsa")]
    Dsa(tc_dsa_key::DsaPublicKey),
    #[cfg(feature = "elgamal")]
    ElGamal(tc_elgamal::ElGamalPublicKey),
    #[cfg(feature = "gost3410")]
    Gost3410(tc_gost3410_key::Gost3410PublicKey),
    #[cfg(feature = "ml-kem")]
    MlKem(tc_ml_kem::MlKemPublicKey),
    #[cfg(feature = "naccache-stern")]
    NaccacheStern(tc_naccache_stern::NaccacheSternPublicKey),
}

// tc_rsa's key has no Debug, as one type holds both public and private keys, so this shows only
// the algorithm
impl fmt::Debug for AnyPublicKey {
    #[allow(unused_variables, reason = "f is unused when every key feature is off")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => f.debug_tuple("Rsa").finish_non_exhaustive(),
            #[cfg(feature = "ec")]
            Self::Ec(_) => f.debug_tuple("Ec").finish_non_exhaustive(),
            #[cfg(feature = "x25519")]
            Self::X25519(_) => f.debug_tuple("X25519").finish_non_exhaustive(),
            #[cfg(feature = "x448")]
            Self::X448(_) => f.debug_tuple("X448").finish_non_exhaustive(),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(_) => f.debug_tuple("Ed25519").finish_non_exhaustive(),
            #[cfg(feature = "ed448")]
            Self::Ed448(_) => f.debug_tuple("Ed448").finish_non_exhaustive(),
            #[cfg(feature = "dh")]
            Self::Dh(_) => f.debug_tuple("Dh").finish_non_exhaustive(),
            #[cfg(feature = "dsa")]
            Self::Dsa(_) => f.debug_tuple("Dsa").finish_non_exhaustive(),
            #[cfg(feature = "elgamal")]
            Self::ElGamal(_) => f.debug_tuple("ElGamal").finish_non_exhaustive(),
            #[cfg(feature = "gost3410")]
            Self::Gost3410(_) => f.debug_tuple("Gost3410").finish_non_exhaustive(),
            #[cfg(feature = "ml-kem")]
            Self::MlKem(_) => f.debug_tuple("MlKem").finish_non_exhaustive(),
            #[cfg(feature = "naccache-stern")]
            Self::NaccacheStern(_) => f.debug_tuple("NaccacheStern").finish_non_exhaustive(),
        }
    }
}
