use super::table::DIGESTS;
use super::{AnyDigest, DigestEntry};

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
}

impl Algorithm {
    /// 每個啟用的演算法在表裡都要有一列；找不到就是表沒補齊。
    pub fn entry(self) -> &'static DigestEntry {
        DIGESTS
            .iter()
            .find(|entry| entry.algorithm() == self)
            .expect("every enabled digest has a table entry")
    }

    /// 用 enum 指定一定認得，所以不會失敗；同樣不受 env 開關影響。
    pub fn create(self) -> AnyDigest {
        self.entry().create()
    }
}
