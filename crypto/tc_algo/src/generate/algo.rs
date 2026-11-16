#[cfg(any(
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
))]
mod aead;
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
    feature = "idea",
    feature = "noekeon",
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
#[cfg(any(
    feature = "aes",
    feature = "aria",
    feature = "blowfish",
    feature = "camellia",
    feature = "cast5",
    feature = "cast6",
    feature = "des",
    feature = "desede",
    feature = "idea",
    feature = "noekeon",
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
    feature = "chacha",
    feature = "chacha20-poly1305",
    feature = "xchacha20",
    feature = "xchacha20-poly1305",
    feature = "hc128",
    feature = "hc256",
    feature = "rc4",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
))]
mod fixed;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
mod key;
#[cfg(feature = "ml-kem")]
mod ml_kem;
#[cfg(feature = "naccache-stern")]
mod naccache_stern;
#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
))]
mod own;
#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "aes",
    feature = "aria",
    feature = "blowfish",
    feature = "camellia",
    feature = "cast5",
    feature = "cast6",
    feature = "des",
    feature = "desede",
    feature = "idea",
    feature = "noekeon",
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
    feature = "chacha",
    feature = "chacha20-poly1305",
    feature = "xchacha20",
    feature = "xchacha20-poly1305",
    feature = "hc128",
    feature = "hc256",
    feature = "rc4",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "ascon-aead128",
    feature = "ascon128",
    feature = "ascon128a",
    feature = "ascon80pq",
    feature = "grain128-aead",
    feature = "schwaemm128-128",
    feature = "schwaemm256-128",
    feature = "schwaemm192-192",
    feature = "schwaemm256-256",
))]
mod random;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "sm2")]
mod sm2;
#[cfg(any(
    feature = "chacha",
    feature = "chacha20-poly1305",
    feature = "xchacha20",
    feature = "xchacha20-poly1305",
    feature = "hc128",
    feature = "hc256",
    feature = "rc4",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
))]
mod stream;

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
        feature = "idea",
        feature = "noekeon",
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
    #[cfg(any(
        feature = "rc2",
        feature = "rc5",
        feature = "rc5-64",
        feature = "gost28147",
    ))]
    own::own,
    #[cfg(any(
        feature = "chacha",
        feature = "chacha20-poly1305",
        feature = "xchacha20",
        feature = "xchacha20-poly1305",
        feature = "hc128",
        feature = "hc256",
        feature = "rc4",
        feature = "salsa20",
        feature = "xsalsa20",
        feature = "vmpc",
        feature = "vmpc-ksa3",
    ))]
    stream::stream,
    #[cfg(any(
        feature = "ascon-aead128",
        feature = "ascon128",
        feature = "ascon128a",
        feature = "ascon80pq",
        feature = "grain128-aead",
        feature = "schwaemm128-128",
        feature = "schwaemm256-128",
        feature = "schwaemm192-192",
        feature = "schwaemm256-256",
    ))]
    aead::aead,
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
