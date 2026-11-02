// What a generator is to make, as plain data: the generator checks it in init. One variant per
// kind of Bouncy Castle KeyGenerationParameters; the DSA, ElGamal, GOST and ML-KEM ones come with
// their generators
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeyGenParams {
    // The size alone, Bouncy Castle's KeyGenerationParameters
    Strength {
        bits: usize,
    },
    #[cfg(feature = "rsa")]
    Rsa(super::RsaKeyGenParams),
    // Bouncy Castle's ECKeyGenerationParameters: the curve is always named
    #[cfg(feature = "ec")]
    Ec {
        curve: crate::params::EcCurve,
    },
    // Bouncy Castle's DHKeyGenerationParameters: the group, which both parties share, such as one
    // of tc_dh_key::standard_groups or that of the other party's public key
    #[cfg(feature = "dh")]
    Dh(tc_dh_key::DhParameters),
}

impl KeyGenParams {
    // Bouncy Castle's defaults: exponent 65537, 2048 bits and certainty 100. Each with_ method of
    // the result changes one of them, and init takes the result as it is
    #[cfg(feature = "rsa")]
    pub const fn rsa() -> super::RsaKeyGenParams {
        super::RsaKeyGenParams::DEFAULT
    }

    #[cfg(feature = "ec")]
    pub const fn ec(curve: crate::params::EcCurve) -> Self {
        Self::Ec { curve }
    }
}

#[cfg(feature = "ec")]
impl From<crate::params::EcCurve> for KeyGenParams {
    fn from(curve: crate::params::EcCurve) -> Self {
        Self::Ec { curve }
    }
}

#[cfg(feature = "dh")]
impl From<tc_dh_key::DhParameters> for KeyGenParams {
    fn from(params: tc_dh_key::DhParameters) -> Self {
        Self::Dh(params)
    }
}
