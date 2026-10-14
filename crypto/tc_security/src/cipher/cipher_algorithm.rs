#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    #[cfg(feature = "aes")]
    Aes,
    #[cfg(feature = "aria")]
    Aria,
    #[cfg(feature = "rc2")]
    Rc2,
    #[cfg(feature = "rc5")]
    Rc5,
    #[cfg(feature = "rc5")]
    Rc5_64,
    #[cfg(feature = "rc6")]
    Rc6,
    #[cfg(feature = "chacha")]
    ChaCha,
    #[cfg(feature = "chacha")]
    ChaCha7539,
    #[cfg(feature = "chacha")]
    XChaCha20,
    #[cfg(feature = "ascon")]
    AsconAead128,
    #[cfg(feature = "ascon")]
    Ascon128,
    #[cfg(feature = "ascon")]
    Ascon128a,
    #[cfg(feature = "ascon")]
    Ascon80pq,
    #[cfg(feature = "rsa")]
    Rsa,
}
