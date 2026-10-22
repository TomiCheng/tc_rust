/// EC 的具名曲線，產生金鑰時用 [`KeyGenParams::Ec`](crate::generate::KeyGenParams::Ec) 指定。
///
/// `ec` 有 secp224k1 到 secp521r1 與 sm2p256v1；`ec-f2m` 加上 sect233k1 到 sect571r1；
/// `ec-small-curves` 加上強度不足、只為互通的小曲線，連同 192 bits 以下的二元體曲線。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EcCurve {
    #[cfg(feature = "ec-small-curves")]
    Secp112r1,
    #[cfg(feature = "ec-small-curves")]
    Secp112r2,
    #[cfg(feature = "ec-small-curves")]
    Secp128r1,
    #[cfg(feature = "ec-small-curves")]
    Secp128r2,
    #[cfg(feature = "ec-small-curves")]
    Secp160k1,
    #[cfg(feature = "ec-small-curves")]
    Secp160r1,
    #[cfg(feature = "ec-small-curves")]
    Secp160r2,
    #[cfg(feature = "ec-small-curves")]
    Secp192k1,
    /// P-192（prime192v1）
    #[cfg(feature = "ec-small-curves")]
    Secp192r1,
    Secp224k1,
    /// P-224
    Secp224r1,
    Secp256k1,
    /// P-256（prime256v1）
    Secp256r1,
    /// P-384
    Secp384r1,
    /// P-521
    Secp521r1,
    /// GM/T 0003 的 SM2 曲線
    Sm2p256v1,
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect113r1,
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect113r2,
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect131r1,
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect131r2,
    /// K-163
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163k1,
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163r1,
    /// B-163
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect163r2,
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect193r1,
    #[cfg(all(feature = "ec-f2m", feature = "ec-small-curves"))]
    Sect193r2,
    /// K-233
    #[cfg(feature = "ec-f2m")]
    Sect233k1,
    /// B-233
    #[cfg(feature = "ec-f2m")]
    Sect233r1,
    #[cfg(feature = "ec-f2m")]
    Sect239k1,
    /// K-283
    #[cfg(feature = "ec-f2m")]
    Sect283k1,
    /// B-283
    #[cfg(feature = "ec-f2m")]
    Sect283r1,
    /// K-409
    #[cfg(feature = "ec-f2m")]
    Sect409k1,
    /// B-409
    #[cfg(feature = "ec-f2m")]
    Sect409r1,
    /// K-571
    #[cfg(feature = "ec-f2m")]
    Sect571k1,
    /// B-571
    #[cfg(feature = "ec-f2m")]
    Sect571r1,
}
