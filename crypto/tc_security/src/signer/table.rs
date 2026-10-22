//! 每種簽章一列；各自的 feature 關掉時，這個演算法就不會出現。

#[cfg(any(feature = "ed25519", feature = "ed448"))]
mod cfrg;
// RSA 簽章一列一個 digest，沒有任何 digest 時就沒有 RSA 簽章
#[cfg(all(
    feature = "rsa",
    any(
        feature = "md2",
        feature = "md4",
        feature = "md5",
        feature = "sha1",
        feature = "sha224",
        feature = "sha256",
        feature = "sha384",
        feature = "sha512",
        feature = "sha512-224",
        feature = "sha512-256"
    )
))]
mod rsa;

use super::SignerEntry;

pub(super) const SIGNERS: &[SignerEntry] = &[
    #[cfg(all(feature = "rsa", feature = "md2"))]
    rsa::MD2,
    #[cfg(all(feature = "rsa", feature = "md4"))]
    rsa::MD4,
    #[cfg(all(feature = "rsa", feature = "md5"))]
    rsa::MD5,
    #[cfg(all(feature = "rsa", feature = "sha1"))]
    rsa::SHA1,
    #[cfg(all(feature = "rsa", feature = "sha224"))]
    rsa::SHA224,
    #[cfg(all(feature = "rsa", feature = "sha256"))]
    rsa::SHA256,
    #[cfg(all(feature = "rsa", feature = "sha384"))]
    rsa::SHA384,
    #[cfg(all(feature = "rsa", feature = "sha512"))]
    rsa::SHA512,
    #[cfg(all(feature = "rsa", feature = "sha512-224"))]
    rsa::SHA512_224,
    #[cfg(all(feature = "rsa", feature = "sha512-256"))]
    rsa::SHA512_256,
    #[cfg(feature = "ed25519")]
    cfrg::ED25519,
    #[cfg(feature = "ed25519")]
    cfrg::ED25519CTX,
    #[cfg(feature = "ed25519")]
    cfrg::ED25519PH,
    #[cfg(feature = "ed448")]
    cfrg::ED448,
    #[cfg(feature = "ed448")]
    cfrg::ED448PH,
];
