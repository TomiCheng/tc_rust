mod row;

#[cfg(feature = "ascon-hash")]
mod ascon;
#[cfg(feature = "blake")]
mod blake;
#[cfg(feature = "dstu7564")]
mod dstu7564;
#[cfg(feature = "gost3411")]
mod gost3411;
#[cfg(feature = "misc-digest")]
mod haraka;
#[cfg(feature = "keccak")]
mod keccak;
#[cfg(feature = "md")]
mod md;
#[cfg(feature = "misc-digest")]
mod misc;
mod null;
#[cfg(feature = "ripemd")]
mod ripemd;
#[cfg(feature = "sha")]
mod sha;
#[cfg(feature = "skein")]
mod skein;
#[cfg(feature = "sm3")]
mod sm3;

use super::DigestEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the digests whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "sha")]
    sha::sha1,
    #[cfg(feature = "sha")]
    sha::sha224,
    #[cfg(feature = "sha")]
    sha::sha256,
    #[cfg(feature = "sha")]
    sha::sha384,
    #[cfg(feature = "sha")]
    sha::sha512,
    #[cfg(feature = "sha")]
    sha::sha512_224,
    #[cfg(feature = "sha")]
    sha::sha512_256,
    #[cfg(feature = "md")]
    md::md2,
    #[cfg(feature = "md")]
    md::md4,
    #[cfg(feature = "md")]
    md::md5,
    #[cfg(feature = "blake")]
    blake::blake2b_160,
    #[cfg(feature = "blake")]
    blake::blake2b_256,
    #[cfg(feature = "blake")]
    blake::blake2b_384,
    #[cfg(feature = "blake")]
    blake::blake2b_512,
    #[cfg(feature = "blake")]
    blake::blake2s_128,
    #[cfg(feature = "blake")]
    blake::blake2s_160,
    #[cfg(feature = "blake")]
    blake::blake2s_224,
    #[cfg(feature = "blake")]
    blake::blake2s_256,
    #[cfg(feature = "blake")]
    blake::blake3_256,
    #[cfg(feature = "ripemd")]
    ripemd::ripemd128,
    #[cfg(feature = "ripemd")]
    ripemd::ripemd160,
    #[cfg(feature = "ripemd")]
    ripemd::ripemd256,
    #[cfg(feature = "ripemd")]
    ripemd::ripemd320,
    #[cfg(feature = "sm3")]
    sm3::sm3,
    #[cfg(feature = "gost3411")]
    gost3411::gost3411,
    #[cfg(feature = "gost3411")]
    gost3411::gost3411_2012_256,
    #[cfg(feature = "gost3411")]
    gost3411::gost3411_2012_512,
    #[cfg(feature = "dstu7564")]
    dstu7564::dstu7564_256,
    #[cfg(feature = "dstu7564")]
    dstu7564::dstu7564_384,
    #[cfg(feature = "dstu7564")]
    dstu7564::dstu7564_512,
    #[cfg(feature = "misc-digest")]
    misc::tiger,
    #[cfg(feature = "misc-digest")]
    misc::whirlpool,
    #[cfg(feature = "keccak")]
    keccak::keccak_224,
    #[cfg(feature = "keccak")]
    keccak::keccak_256,
    #[cfg(feature = "keccak")]
    keccak::keccak_288,
    #[cfg(feature = "keccak")]
    keccak::keccak_384,
    #[cfg(feature = "keccak")]
    keccak::keccak_512,
    #[cfg(feature = "keccak")]
    keccak::sha3_224,
    #[cfg(feature = "keccak")]
    keccak::sha3_256,
    #[cfg(feature = "keccak")]
    keccak::sha3_384,
    #[cfg(feature = "keccak")]
    keccak::sha3_512,
    #[cfg(feature = "keccak")]
    keccak::shake128_256,
    #[cfg(feature = "keccak")]
    keccak::shake256_512,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_hash256,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_hash,
    #[cfg(feature = "ascon-hash")]
    ascon::ascon_hasha,
    #[cfg(feature = "ascon-hash")]
    ascon::isap,
    #[cfg(feature = "skein")]
    skein::skein_256_128,
    #[cfg(feature = "skein")]
    skein::skein_256_160,
    #[cfg(feature = "skein")]
    skein::skein_256_224,
    #[cfg(feature = "skein")]
    skein::skein_256_256,
    #[cfg(feature = "skein")]
    skein::skein_512_128,
    #[cfg(feature = "skein")]
    skein::skein_512_160,
    #[cfg(feature = "skein")]
    skein::skein_512_224,
    #[cfg(feature = "skein")]
    skein::skein_512_256,
    #[cfg(feature = "skein")]
    skein::skein_512_384,
    #[cfg(feature = "skein")]
    skein::skein_512_512,
    #[cfg(feature = "skein")]
    skein::skein_1024_384,
    #[cfg(feature = "skein")]
    skein::skein_1024_512,
    #[cfg(feature = "skein")]
    skein::skein_1024_1024,
    #[cfg(feature = "misc-digest")]
    misc::photon_beetle,
    #[cfg(feature = "misc-digest")]
    misc::esch_256,
    #[cfg(feature = "misc-digest")]
    misc::esch_384,
    #[cfg(feature = "misc-digest")]
    misc::xoodyak,
    #[cfg(feature = "misc-digest")]
    haraka::haraka256,
    #[cfg(feature = "misc-digest")]
    haraka::haraka512,
    null::null_digest,
];
