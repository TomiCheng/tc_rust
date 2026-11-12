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
    feature = "null-digest",
))]
mod row;

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
#[cfg(any(feature = "md2", feature = "md4", feature = "md5",))]
mod md;
#[cfg(any(feature = "tiger", feature = "whirlpool",))]
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
    #[cfg(feature = "null-digest")]
    null::null_digest,
];
