#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
))]
mod aead_mode;
#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "aria")]
mod aria;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
))]
mod block;
#[cfg(feature = "blowfish")]
mod blowfish;
#[cfg(any(
    feature = "aes",
    feature = "des",
    feature = "desede",
    feature = "camellia",
    feature = "aria",
    feature = "sm4",
    feature = "seed",
    feature = "blowfish",
    feature = "twofish",
    feature = "serpent",
    feature = "tnepres",
    feature = "cast5",
    feature = "cast6",
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea",
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "rc6",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024",
))]
mod buffered;
#[cfg(feature = "camellia")]
mod camellia;
#[cfg(feature = "cast5")]
mod cast5;
#[cfg(feature = "cast6")]
mod cast6;
#[cfg(any(feature = "chacha", feature = "xchacha20"))]
mod chacha;
#[cfg(any(feature = "des", feature = "desede"))]
mod des;
#[cfg(feature = "gost28147")]
mod gost28147;
#[cfg(any(feature = "hc128", feature = "hc256"))]
mod hc;
#[cfg(feature = "idea")]
mod idea;
#[cfg(feature = "ies")]
mod ies;
#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
mod keyed;
#[cfg(feature = "noekeon")]
mod noekeon;
#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64", feature = "rc6"))]
mod rc;
#[cfg(any(
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac"
))]
mod rc4;
#[cfg(feature = "rijndael")]
mod rijndael;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(any(feature = "salsa20", feature = "xsalsa20"))]
mod salsa20;
#[cfg(feature = "seed")]
mod seed;
#[cfg(feature = "serpent")]
mod serpent;
#[cfg(feature = "skipjack")]
mod skipjack;
#[cfg(feature = "sm4")]
mod sm4;
#[cfg(any(
    feature = "chacha",
    feature = "xchacha20",
    feature = "rc4",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "isaac",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
))]
mod stream;
#[cfg(feature = "tea")]
mod tea;
#[cfg(any(
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
mod threefish;
#[cfg(feature = "tnepres")]
mod tnepres;
#[cfg(feature = "twofish")]
mod twofish;
#[cfg(feature = "xtea")]
mod xtea;

use super::CipherEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the ciphers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "aes")]
    aes::aes,
    #[cfg(feature = "des")]
    des::des,
    #[cfg(feature = "desede")]
    des::desede,
    #[cfg(feature = "camellia")]
    camellia::camellia,
    #[cfg(feature = "aria")]
    aria::aria,
    #[cfg(feature = "sm4")]
    sm4::sm4,
    #[cfg(feature = "seed")]
    seed::seed,
    #[cfg(feature = "blowfish")]
    blowfish::blowfish,
    #[cfg(feature = "twofish")]
    twofish::twofish,
    #[cfg(feature = "serpent")]
    serpent::serpent,
    #[cfg(feature = "tnepres")]
    tnepres::tnepres,
    #[cfg(feature = "cast5")]
    cast5::cast5,
    #[cfg(feature = "cast6")]
    cast6::cast6,
    #[cfg(feature = "idea")]
    idea::idea,
    #[cfg(feature = "noekeon")]
    noekeon::noekeon,
    #[cfg(feature = "rijndael")]
    rijndael::rijndael,
    #[cfg(feature = "skipjack")]
    skipjack::skipjack,
    #[cfg(feature = "tea")]
    tea::tea,
    #[cfg(feature = "xtea")]
    xtea::xtea,
    #[cfg(feature = "rc2")]
    rc::rc2,
    #[cfg(feature = "rc5")]
    rc::rc5,
    #[cfg(feature = "rc5-64")]
    rc::rc5_64,
    #[cfg(feature = "rc6")]
    rc::rc6,
    #[cfg(feature = "gost28147")]
    gost28147::gost28147,
    #[cfg(feature = "threefish-256")]
    threefish::threefish_256,
    #[cfg(feature = "threefish-512")]
    threefish::threefish_512,
    #[cfg(feature = "threefish-1024")]
    threefish::threefish_1024,
    #[cfg(feature = "chacha")]
    chacha::chacha,
    #[cfg(feature = "xchacha20")]
    chacha::xchacha20,
    #[cfg(feature = "rc4")]
    rc4::rc4,
    #[cfg(feature = "vmpc")]
    rc4::vmpc,
    #[cfg(feature = "vmpc-ksa3")]
    rc4::vmpc_ksa3,
    #[cfg(feature = "isaac")]
    rc4::isaac,
    #[cfg(feature = "salsa20")]
    salsa20::salsa20,
    #[cfg(feature = "xsalsa20")]
    salsa20::xsalsa20,
    #[cfg(feature = "hc128")]
    hc::hc128,
    #[cfg(feature = "hc256")]
    hc::hc256,
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "ies")]
    ies::ies,
];
