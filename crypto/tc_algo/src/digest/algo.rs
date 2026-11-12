#[cfg(any(
    feature = "sha1",
    feature = "sha224",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512",
    feature = "sha512-224",
    feature = "sha512-256",
    feature = "md2",
    feature = "md4",
    feature = "md5",
    feature = "blake2b-160",
    feature = "blake2b-256",
    feature = "blake2b-384",
    feature = "blake2b-512",
    feature = "blake2s-128",
    feature = "blake2s-160",
    feature = "blake2s-224",
    feature = "blake2s-256",
    feature = "blake3-256",
    feature = "ripemd128",
    feature = "ripemd160",
    feature = "ripemd256",
    feature = "ripemd320",
    feature = "sm3",
    feature = "gost3411",
    feature = "gost3411-2012-256",
    feature = "gost3411-2012-512",
    feature = "dstu7564-256",
    feature = "dstu7564-384",
    feature = "dstu7564-512",
    feature = "tiger",
    feature = "whirlpool",
    feature = "keccak-224",
    feature = "keccak-256",
    feature = "keccak-288",
    feature = "keccak-384",
    feature = "keccak-512",
    feature = "sha3-224",
    feature = "sha3-256",
    feature = "sha3-384",
    feature = "sha3-512",
    feature = "shake128-256",
    feature = "shake256-512",
    feature = "ascon-hash256",
    feature = "ascon-hash",
    feature = "ascon-hasha",
    feature = "isap",
    feature = "skein-256-128",
    feature = "skein-256-160",
    feature = "skein-256-224",
    feature = "skein-256-256",
    feature = "skein-512-128",
    feature = "skein-512-160",
    feature = "skein-512-224",
    feature = "skein-512-256",
    feature = "skein-512-384",
    feature = "skein-512-512",
    feature = "skein-1024-384",
    feature = "skein-1024-512",
    feature = "skein-1024-1024",
    feature = "photon-beetle",
    feature = "esch-256",
    feature = "esch-384",
    feature = "xoodyak",
    feature = "null-digest",
))]
mod row;

#[cfg(any(
    feature = "ascon-hash256",
    feature = "ascon-hash",
    feature = "ascon-hasha",
    feature = "isap",
))]
mod ascon;
#[cfg(any(
    feature = "blake2b-160",
    feature = "blake2b-256",
    feature = "blake2b-384",
    feature = "blake2b-512",
    feature = "blake2s-128",
    feature = "blake2s-160",
    feature = "blake2s-224",
    feature = "blake2s-256",
    feature = "blake3-256",
))]
mod blake;
#[cfg(any(
    feature = "dstu7564-256",
    feature = "dstu7564-384",
    feature = "dstu7564-512",
))]
mod dstu7564;
#[cfg(any(
    feature = "gost3411",
    feature = "gost3411-2012-256",
    feature = "gost3411-2012-512",
))]
mod gost3411;
#[cfg(any(feature = "haraka-256", feature = "haraka-512",))]
mod haraka;
#[cfg(any(
    feature = "keccak-224",
    feature = "keccak-256",
    feature = "keccak-288",
    feature = "keccak-384",
    feature = "keccak-512",
    feature = "sha3-224",
    feature = "sha3-256",
    feature = "sha3-384",
    feature = "sha3-512",
    feature = "shake128-256",
    feature = "shake256-512",
))]
mod keccak;
#[cfg(any(feature = "md2", feature = "md4", feature = "md5",))]
mod md;
#[cfg(any(
    feature = "tiger",
    feature = "whirlpool",
    feature = "photon-beetle",
    feature = "esch-256",
    feature = "esch-384",
    feature = "xoodyak",
))]
mod misc;
#[cfg(feature = "null-digest")]
mod null;
#[cfg(any(
    feature = "ripemd128",
    feature = "ripemd160",
    feature = "ripemd256",
    feature = "ripemd320",
))]
mod ripemd;
#[cfg(any(
    feature = "sha1",
    feature = "sha224",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512",
    feature = "sha512-224",
    feature = "sha512-256",
))]
mod sha;
#[cfg(any(
    feature = "skein-256-128",
    feature = "skein-256-160",
    feature = "skein-256-224",
    feature = "skein-256-256",
    feature = "skein-512-128",
    feature = "skein-512-160",
    feature = "skein-512-224",
    feature = "skein-512-256",
    feature = "skein-512-384",
    feature = "skein-512-512",
    feature = "skein-1024-384",
    feature = "skein-1024-512",
    feature = "skein-1024-1024",
))]
mod skein;
#[cfg(feature = "sm3")]
mod sm3;

use super::DigestEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the digests whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "sha1")]
    sha::sha1,
    #[cfg(feature = "sha224")]
    sha::sha224,
    #[cfg(feature = "sha256")]
    sha::sha256,
    #[cfg(feature = "sha384")]
    sha::sha384,
    #[cfg(feature = "sha512")]
    sha::sha512,
    #[cfg(feature = "sha512-224")]
    sha::sha512_224,
    #[cfg(feature = "sha512-256")]
    sha::sha512_256,
    #[cfg(feature = "md2")]
    md::md2,
    #[cfg(feature = "md4")]
    md::md4,
    #[cfg(feature = "md5")]
    md::md5,
    #[cfg(feature = "blake2b-160")]
    blake::blake2b_160,
    #[cfg(feature = "blake2b-256")]
    blake::blake2b_256,
    #[cfg(feature = "blake2b-384")]
    blake::blake2b_384,
    #[cfg(feature = "blake2b-512")]
    blake::blake2b_512,
    #[cfg(feature = "blake2s-128")]
    blake::blake2s_128,
    #[cfg(feature = "blake2s-160")]
    blake::blake2s_160,
    #[cfg(feature = "blake2s-224")]
    blake::blake2s_224,
    #[cfg(feature = "blake2s-256")]
    blake::blake2s_256,
    #[cfg(feature = "blake3-256")]
    blake::blake3_256,
    #[cfg(feature = "ripemd128")]
    ripemd::ripemd128,
    #[cfg(feature = "ripemd160")]
    ripemd::ripemd160,
    #[cfg(feature = "ripemd256")]
    ripemd::ripemd256,
    #[cfg(feature = "ripemd320")]
    ripemd::ripemd320,
    #[cfg(feature = "sm3")]
    sm3::sm3,
    #[cfg(feature = "gost3411")]
    gost3411::gost3411,
    #[cfg(feature = "gost3411-2012-256")]
    gost3411::gost3411_2012_256,
    #[cfg(feature = "gost3411-2012-512")]
    gost3411::gost3411_2012_512,
    #[cfg(feature = "dstu7564-256")]
    dstu7564::dstu7564_256,
    #[cfg(feature = "dstu7564-384")]
    dstu7564::dstu7564_384,
    #[cfg(feature = "dstu7564-512")]
    dstu7564::dstu7564_512,
    #[cfg(feature = "tiger")]
    misc::tiger,
    #[cfg(feature = "whirlpool")]
    misc::whirlpool,
    #[cfg(feature = "keccak-224")]
    keccak::keccak_224,
    #[cfg(feature = "keccak-256")]
    keccak::keccak_256,
    #[cfg(feature = "keccak-288")]
    keccak::keccak_288,
    #[cfg(feature = "keccak-384")]
    keccak::keccak_384,
    #[cfg(feature = "keccak-512")]
    keccak::keccak_512,
    #[cfg(feature = "sha3-224")]
    keccak::sha3_224,
    #[cfg(feature = "sha3-256")]
    keccak::sha3_256,
    #[cfg(feature = "sha3-384")]
    keccak::sha3_384,
    #[cfg(feature = "sha3-512")]
    keccak::sha3_512,
    #[cfg(feature = "shake128-256")]
    keccak::shake128_256,
    #[cfg(feature = "shake256-512")]
    keccak::shake256_512,
    #[cfg(feature = "ascon-hash256")]
    ascon::ascon_hash256,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_hash,
    #[cfg(feature = "ascon-hasha")]
    ascon::ascon_hasha,
    #[cfg(feature = "isap")]
    ascon::isap,
    #[cfg(feature = "skein-256-128")]
    skein::skein_256_128,
    #[cfg(feature = "skein-256-160")]
    skein::skein_256_160,
    #[cfg(feature = "skein-256-224")]
    skein::skein_256_224,
    #[cfg(feature = "skein-256-256")]
    skein::skein_256_256,
    #[cfg(feature = "skein-512-128")]
    skein::skein_512_128,
    #[cfg(feature = "skein-512-160")]
    skein::skein_512_160,
    #[cfg(feature = "skein-512-224")]
    skein::skein_512_224,
    #[cfg(feature = "skein-512-256")]
    skein::skein_512_256,
    #[cfg(feature = "skein-512-384")]
    skein::skein_512_384,
    #[cfg(feature = "skein-512-512")]
    skein::skein_512_512,
    #[cfg(feature = "skein-1024-384")]
    skein::skein_1024_384,
    #[cfg(feature = "skein-1024-512")]
    skein::skein_1024_512,
    #[cfg(feature = "skein-1024-1024")]
    skein::skein_1024_1024,
    #[cfg(feature = "photon-beetle")]
    misc::photon_beetle,
    #[cfg(feature = "esch-256")]
    misc::esch_256,
    #[cfg(feature = "esch-384")]
    misc::esch_384,
    #[cfg(feature = "xoodyak")]
    misc::xoodyak,
    #[cfg(feature = "haraka-256")]
    haraka::haraka256,
    #[cfg(feature = "haraka-512")]
    haraka::haraka512,
    #[cfg(feature = "null-digest")]
    null::null_digest,
];
