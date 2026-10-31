use super::DigestEntry;
use super::table::DIGESTS;

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    #[cfg(feature = "md2")]
    Md2,
    #[cfg(feature = "md4")]
    Md4,
    #[cfg(feature = "md5")]
    Md5,
    #[cfg(feature = "sha1")]
    Sha1,
    #[cfg(feature = "sha224")]
    Sha224,
    #[cfg(feature = "sha256")]
    Sha256,
    #[cfg(feature = "sha384")]
    Sha384,
    #[cfg(feature = "sha512")]
    Sha512,
    #[cfg(feature = "sha512-224")]
    Sha512_224,
    #[cfg(feature = "sha512-256")]
    Sha512_256,
    #[cfg(feature = "sha3-224")]
    Sha3_224,
    #[cfg(feature = "sha3-256")]
    Sha3_256,
    #[cfg(feature = "sha3-384")]
    Sha3_384,
    #[cfg(feature = "sha3-512")]
    Sha3_512,
    #[cfg(feature = "keccak-224")]
    Keccak224,
    #[cfg(feature = "keccak-256")]
    Keccak256,
    #[cfg(feature = "keccak-288")]
    Keccak288,
    #[cfg(feature = "keccak-384")]
    Keccak384,
    #[cfg(feature = "keccak-512")]
    Keccak512,
    #[cfg(feature = "shake128")]
    Shake128,
    #[cfg(feature = "shake256")]
    Shake256,
    #[cfg(feature = "blake2b-160")]
    Blake2b160,
    #[cfg(feature = "blake2b-256")]
    Blake2b256,
    #[cfg(feature = "blake2b-384")]
    Blake2b384,
    #[cfg(feature = "blake2b-512")]
    Blake2b512,
    #[cfg(feature = "blake2s-128")]
    Blake2s128,
    #[cfg(feature = "blake2s-160")]
    Blake2s160,
    #[cfg(feature = "blake2s-224")]
    Blake2s224,
    #[cfg(feature = "blake2s-256")]
    Blake2s256,
    #[cfg(feature = "blake3-256")]
    Blake3_256,
    #[cfg(feature = "dstu7564-256")]
    Dstu7564_256,
    #[cfg(feature = "dstu7564-384")]
    Dstu7564_384,
    #[cfg(feature = "dstu7564-512")]
    Dstu7564_512,
    #[cfg(feature = "gost3411")]
    Gost3411,
    #[cfg(feature = "gost3411-2012-256")]
    Gost3411_2012_256,
    #[cfg(feature = "gost3411-2012-512")]
    Gost3411_2012_512,
    #[cfg(feature = "ripemd128")]
    Ripemd128,
    #[cfg(feature = "ripemd160")]
    Ripemd160,
    #[cfg(feature = "ripemd256")]
    Ripemd256,
    #[cfg(feature = "ripemd320")]
    Ripemd320,
    #[cfg(feature = "sm3")]
    Sm3,
    #[cfg(feature = "tiger")]
    Tiger,
    #[cfg(feature = "whirlpool")]
    Whirlpool,
    #[cfg(feature = "null-digest")]
    Null,
}

impl Algorithm {
    // Every enabled algorithm has a table row; a missing one means the table is incomplete
    #[allow(
        unreachable_code,
        reason = "Algorithm has no values when every digest feature is off"
    )]
    pub fn entry(self) -> &'static DigestEntry {
        DIGESTS
            .iter()
            .find(|entry| entry.algorithm() == self)
            .expect("every enabled digest has a table entry")
    }
}
