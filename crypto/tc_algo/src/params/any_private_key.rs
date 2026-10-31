use core::fmt;

// One variant per algorithm, each holding the key type of the crate that implements it
#[derive(Clone)]
#[non_exhaustive]
pub enum AnyPrivateKey {
    // A key whose exponent is d, or a key with its CRT values
    #[cfg(feature = "rsa")]
    Rsa(tc_rsa::RsaKey),
    #[cfg(feature = "ec")]
    Ec(super::AnyEcPrivateKey),
}

// The key types have no Debug, which would show their private values; this shows only the
// algorithm
impl fmt::Debug for AnyPrivateKey {
    #[allow(unused_variables, reason = "f is unused when every key feature is off")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => f.debug_tuple("Rsa").finish_non_exhaustive(),
            #[cfg(feature = "ec")]
            Self::Ec(_) => f.debug_tuple("Ec").finish_non_exhaustive(),
        }
    }
}
