// The named EC curves. `ec` has secp224k1 to secp521r1 and sm2p256v1; `ec-f2m` adds sect233k1
// to sect571r1; `ec-small-curves` adds the weak curves kept only for interoperability, and with
// `ec-f2m` the binary curves below 233 bits
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
    /// P-192 (prime192v1)
    #[cfg(feature = "ec-small-curves")]
    Secp192r1,
    Secp224k1,
    /// P-224
    Secp224r1,
    Secp256k1,
    /// P-256 (prime256v1)
    Secp256r1,
    /// P-384
    Secp384r1,
    /// P-521
    Secp521r1,
    /// The SM2 curve of GM/T 0003
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
