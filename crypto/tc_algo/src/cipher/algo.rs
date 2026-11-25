#[cfg(any(
    feature = "chacha-aead",
    feature = "ascon-aead",
    feature = "grain128-aead",
    feature = "sparkle-aead"
))]
mod aead_engine;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish"
))]
mod aead_mode;
#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "aria")]
mod aria;
#[cfg(feature = "ascon-aead")]
mod ascon_aead;
#[cfg(any(
    feature = "rsa",
    feature = "elgamal",
    feature = "naccache-stern",
    feature = "sm2"
))]
mod asym;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish"
))]
mod block;
#[cfg(feature = "blowfish")]
mod blowfish;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "dstu7624",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "cast",
    feature = "misc-block-cipher",
    feature = "rc-cipher",
    feature = "gost28147",
    feature = "threefish"
))]
mod buffered;
#[cfg(feature = "camellia")]
mod camellia;
#[cfg(feature = "cast")]
mod cast5;
#[cfg(feature = "cast")]
mod cast6;
#[cfg(feature = "chacha")]
mod chacha;
#[cfg(feature = "chacha-aead")]
mod chacha_aead;
#[cfg(feature = "des")]
mod des;
#[cfg(feature = "dstu7624")]
mod dstu7624;
#[cfg(all(
    feature = "ies",
    feature = "ec-agreement",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
mod ecies;
#[cfg(feature = "elgamal")]
mod elgamal;
#[cfg(feature = "gost28147")]
mod gost28147;
#[cfg(feature = "grain128-aead")]
mod grain128_aead;
#[cfg(feature = "hc")]
mod hc;
#[cfg(feature = "misc-block-cipher")]
mod idea;
#[cfg(feature = "ies")]
mod ies;
#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
mod keyed;
#[cfg(feature = "naccache-stern")]
mod naccache_stern;
#[cfg(feature = "misc-block-cipher")]
mod noekeon;
#[cfg(feature = "rc-cipher")]
mod rc;
#[cfg(feature = "rc4-family")]
mod rc4;
#[cfg(feature = "misc-block-cipher")]
mod rijndael;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "salsa20")]
mod salsa20;
#[cfg(feature = "seed")]
mod seed;
#[cfg(feature = "serpent")]
mod serpent;
#[cfg(feature = "misc-block-cipher")]
mod skipjack;
#[cfg(feature = "sm2")]
mod sm2;
#[cfg(feature = "sm4")]
mod sm4;
#[cfg(feature = "sparkle-aead")]
mod sparkle_aead;
#[cfg(any(
    feature = "chacha",
    feature = "rc4-family",
    feature = "salsa20",
    feature = "hc"
))]
mod stream;
#[cfg(feature = "misc-block-cipher")]
mod tea;
#[cfg(feature = "threefish")]
mod threefish;
#[cfg(feature = "serpent")]
mod tnepres;
#[cfg(feature = "twofish")]
mod twofish;
#[cfg(feature = "misc-block-cipher")]
mod xtea;

use super::CipherEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the ciphers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
    #[cfg(feature = "des")]
    des::des,
    #[cfg(feature = "des")]
    des::desede,
    #[cfg(feature = "camellia")]
    camellia::camellia,
    #[cfg(feature = "aria")]
    aria::aria,
    #[cfg(feature = "sm4")]
    sm4::sm4,
    #[cfg(feature = "seed")]
    seed::seed,
    #[cfg(feature = "dstu7624")]
    dstu7624::dstu7624_128,
    #[cfg(feature = "dstu7624")]
    dstu7624::dstu7624_256,
    #[cfg(feature = "dstu7624")]
    dstu7624::dstu7624_512,
    #[cfg(feature = "blowfish")]
    blowfish::blowfish,
    #[cfg(feature = "twofish")]
    twofish::twofish,
    #[cfg(feature = "serpent")]
    serpent::serpent,
    #[cfg(feature = "serpent")]
    tnepres::tnepres,
    #[cfg(feature = "cast")]
    cast5::cast5,
    #[cfg(feature = "cast")]
    cast6::cast6,
    #[cfg(feature = "misc-block-cipher")]
    idea::idea,
    #[cfg(feature = "misc-block-cipher")]
    noekeon::noekeon,
    #[cfg(feature = "misc-block-cipher")]
    rijndael::rijndael,
    #[cfg(feature = "misc-block-cipher")]
    skipjack::skipjack,
    #[cfg(feature = "misc-block-cipher")]
    tea::tea,
    #[cfg(feature = "misc-block-cipher")]
    xtea::xtea,
    #[cfg(feature = "rc-cipher")]
    rc::rc2,
    #[cfg(feature = "rc-cipher")]
    rc::rc5,
    #[cfg(feature = "rc-cipher")]
    rc::rc5_64,
    #[cfg(feature = "rc-cipher")]
    rc::rc6,
    #[cfg(feature = "gost28147")]
    gost28147::gost28147,
    #[cfg(feature = "threefish")]
    threefish::threefish_256,
    #[cfg(feature = "threefish")]
    threefish::threefish_512,
    #[cfg(feature = "threefish")]
    threefish::threefish_1024,
    #[cfg(feature = "chacha")]
    chacha::chacha,
    #[cfg(feature = "chacha")]
    chacha::xchacha20,
    #[cfg(feature = "chacha-aead")]
    chacha_aead::chacha20_poly1305,
    #[cfg(feature = "chacha-aead")]
    chacha_aead::xchacha20_poly1305,
    #[cfg(feature = "ascon-aead")]
    ascon_aead::ascon_aead128,
    #[cfg(feature = "ascon-aead")]
    ascon_aead::ascon128,
    #[cfg(feature = "ascon-aead")]
    ascon_aead::ascon128a,
    #[cfg(feature = "ascon-aead")]
    ascon_aead::ascon80pq,
    #[cfg(feature = "grain128-aead")]
    grain128_aead::grain128_aead,
    #[cfg(feature = "sparkle-aead")]
    sparkle_aead::schwaemm128_128,
    #[cfg(feature = "sparkle-aead")]
    sparkle_aead::schwaemm256_128,
    #[cfg(feature = "sparkle-aead")]
    sparkle_aead::schwaemm192_192,
    #[cfg(feature = "sparkle-aead")]
    sparkle_aead::schwaemm256_256,
    #[cfg(feature = "rc4-family")]
    rc4::rc4,
    #[cfg(feature = "rc4-family")]
    rc4::vmpc,
    #[cfg(feature = "rc4-family")]
    rc4::vmpc_ksa3,
    #[cfg(feature = "rc4-family")]
    rc4::isaac,
    #[cfg(feature = "salsa20")]
    salsa20::salsa20,
    #[cfg(feature = "salsa20")]
    salsa20::xsalsa20,
    #[cfg(feature = "hc")]
    hc::hc128,
    #[cfg(feature = "hc")]
    hc::hc256,
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "elgamal")]
    elgamal::elgamal,
    #[cfg(feature = "naccache-stern")]
    naccache_stern::naccache_stern,
    #[cfg(feature = "sm2")]
    sm2::sm2,
    #[cfg(feature = "ies")]
    ies::ies,
    #[cfg(all(
        feature = "ies",
        feature = "ec-agreement",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ))]
    ecies::ecies,
];
