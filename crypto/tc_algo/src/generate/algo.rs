#[cfg(feature = "aes")]
mod aes;
#[cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "blowfish",
    feature = "camellia",
    feature = "cast5",
    feature = "cast6",
    feature = "des",
    feature = "desede",
    feature = "gost28147",
    feature = "idea",
    feature = "noekeon",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "rijndael",
    feature = "seed",
    feature = "serpent",
    feature = "skipjack",
    feature = "sm4",
    feature = "tea",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
    feature = "tnepres",
    feature = "twofish",
    feature = "xtea",
))]
mod block;
#[cfg(feature = "dh")]
mod dh;
#[cfg(feature = "ec")]
mod ec;
#[cfg(feature = "elgamal")]
mod elgamal;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
mod key;
#[cfg(feature = "ml-kem")]
mod ml_kem;
#[cfg(feature = "naccache-stern")]
mod naccache_stern;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "sm2")]
mod sm2;

use super::{CreateKeyGeneratorRows, CreateKeyPairGeneratorRows};

// What DefaultAlgoBuilder starts with: the rows of the key generators whose features are on
pub(crate) const BUILT_IN_KEY_GENERATORS: &[CreateKeyGeneratorRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
    #[cfg(any(
        feature = "aes",
        feature = "aria",
        feature = "blowfish",
        feature = "camellia",
        feature = "cast5",
        feature = "cast6",
        feature = "des",
        feature = "desede",
        feature = "gost28147",
        feature = "idea",
        feature = "noekeon",
        feature = "rc2",
        feature = "rc5",
        feature = "rc5-64",
        feature = "rc6",
        feature = "rijndael",
        feature = "seed",
        feature = "serpent",
        feature = "skipjack",
        feature = "sm4",
        feature = "tea",
        feature = "threefish-256",
        feature = "threefish-512",
        feature = "threefish-1024",
        feature = "tnepres",
        feature = "twofish",
        feature = "xtea",
    ))]
    block::block,
    #[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
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
    #[cfg(feature = "ec")]
    ec::ec,
];
