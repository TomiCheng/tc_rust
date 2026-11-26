#[cfg(any(
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead"
))]
mod aead;
#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "cfrg-curves")]
mod agreement_keys;
#[cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "blowfish",
    feature = "camellia",
    feature = "cast",
    feature = "des",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "seed",
    feature = "serpent",
    feature = "sm4",
    feature = "twofish"
))]
mod block;
#[cfg(feature = "dh")]
mod dh;
#[cfg(feature = "dh")]
mod dh_group;
#[cfg(any(
    feature = "fp-custom",
    feature = "fp-curve",
    feature = "f2m-custom",
    feature = "f2m-curve"
))]
mod ec;
#[cfg(feature = "elgamal")]
mod elgamal;
#[cfg(feature = "elgamal")]
mod elgamal_group;
#[cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "blowfish",
    feature = "camellia",
    feature = "cast",
    feature = "des",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "seed",
    feature = "serpent",
    feature = "sm4",
    feature = "twofish",
    feature = "chacha",
    feature = "chacha-aead",
    feature = "hc",
    feature = "rc4-family",
    feature = "salsa20",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead"
))]
mod fixed;
mod key;
#[cfg(feature = "ml-kem")]
mod ml_kem;
#[cfg(feature = "naccache-stern")]
mod naccache_stern;
#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
mod own;
#[cfg(any(
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "aes",
    feature = "aria",
    feature = "blowfish",
    feature = "camellia",
    feature = "cast",
    feature = "des",
    feature = "misc-block-cipher",
    feature = "seed",
    feature = "serpent",
    feature = "sm4",
    feature = "threefish",
    feature = "twofish",
    feature = "chacha",
    feature = "chacha-aead",
    feature = "hc",
    feature = "rc4-family",
    feature = "salsa20",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead"
))]
mod random;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(any(
    feature = "dsa",
    feature = "gost3410",
    feature = "cfrg-curves",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
mod signing_keys;
#[cfg(feature = "sm2")]
mod sm2;
#[cfg(any(
    feature = "chacha",
    feature = "chacha-aead",
    feature = "hc",
    feature = "rc4-family",
    feature = "salsa20"
))]
mod stream;
#[cfg(any(
    feature = "dsa",
    feature = "gost3410",
    feature = "cfrg-curves",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
mod with_params;

use super::{CreateKeyGeneratorRows, CreateKeyPairGeneratorRows, CreateParamsGeneratorRows};

// What DefaultAlgoBuilder starts with: the rows of the key generators whose features are on
pub(crate) const BUILT_IN_KEY_GENERATORS: &[CreateKeyGeneratorRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
    #[cfg(any(
        feature = "aes",
        feature = "aria",
        feature = "blowfish",
        feature = "camellia",
        feature = "cast",
        feature = "des",
        feature = "misc-block-cipher",
        feature = "rc-cipher",
        feature = "seed",
        feature = "serpent",
        feature = "sm4",
        feature = "twofish"
    ))]
    block::block,
    #[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
    own::own,
    #[cfg(any(
        feature = "chacha",
        feature = "chacha-aead",
        feature = "hc",
        feature = "rc4-family",
        feature = "salsa20"
    ))]
    stream::stream,
    #[cfg(any(
        feature = "ascon-aead",
        feature = "grain128-aead",
        feature = "sparkle-aead"
    ))]
    aead::aead,
    key::key,
];

// The same for the key pair generators
pub(crate) const BUILT_IN_KEY_PAIR_GENERATORS: &[CreateKeyPairGeneratorRows] = &[
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "dh")]
    dh::dh,
    #[cfg(feature = "ml-kem")]
    ml_kem::ml_kem,
    #[cfg(feature = "elgamal")]
    elgamal::elgamal,
    #[cfg(feature = "naccache-stern")]
    naccache_stern::naccache_stern,
    #[cfg(feature = "sm2")]
    sm2::sm2,
    #[cfg(any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    ))]
    ec::ec,
    #[cfg(any(
        feature = "dsa",
        feature = "gost3410",
        feature = "cfrg-curves",
        feature = "ml-dsa",
        feature = "slh-dsa"
    ))]
    signing_keys::signing_keys,
    #[cfg(feature = "cfrg-curves")]
    agreement_keys::agreement_keys,
];

// The same for the params generators
pub(crate) const BUILT_IN_PARAMS_GENERATORS: &[CreateParamsGeneratorRows] = &[
    #[cfg(feature = "dh")]
    dh_group::dh_group,
    #[cfg(feature = "elgamal")]
    elgamal_group::elgamal_group,
];
