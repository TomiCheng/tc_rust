// What a generator is to make, as plain data: the generator checks it in init. One variant per
// kind of Bouncy Castle KeyGenerationParameters; the DH, DSA, ElGamal, GOST and ML-KEM ones come
// with their generators
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeyGenParams {
    // The size alone, Bouncy Castle's KeyGenerationParameters
    Strength {
        bits: usize,
    },
    // Bouncy Castle's RsaKeyGenerationParameters
    #[cfg(feature = "rsa")]
    Rsa {
        public_exponent: u32,
        bits: usize,
        certainty: u32,
    },
    // Bouncy Castle's ECKeyGenerationParameters: the curve is always named
    #[cfg(feature = "ec")]
    Ec {
        curve: crate::params::EcCurve,
    },
}
