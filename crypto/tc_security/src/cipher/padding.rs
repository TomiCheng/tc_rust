#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Padding {
    NoPadding,
    Pkcs7,
    Iso10126,
    Iso7816,
    X923,
    Tbc,
    ZeroByte,
    #[cfg(feature = "rsa")]
    Pkcs1,
    #[cfg(all(feature = "rsa", feature = "md5"))]
    OaepMd5,
    #[cfg(all(feature = "rsa", feature = "sha1"))]
    OaepSha1,
    #[cfg(all(feature = "rsa", feature = "sha224"))]
    OaepSha224,
    #[cfg(all(feature = "rsa", feature = "sha256"))]
    OaepSha256,
    #[cfg(all(feature = "rsa", feature = "sha256", feature = "sha1"))]
    OaepSha256Mgf1Sha1,
    #[cfg(all(feature = "rsa", feature = "sha384"))]
    OaepSha384,
    #[cfg(all(feature = "rsa", feature = "sha512"))]
    OaepSha512,
    #[cfg(feature = "iso9796")]
    Iso9796_1,
}
