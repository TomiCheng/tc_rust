/// 產生金鑰的參數，對應 BC 的 `KeyGenerationParameters` 與它的子類別。
///
/// 只是 DTO，不驗證內容：數值合不合用，由產生器在 `init` 判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyGenParams {
    /// 只有長度（bits），對應 BC 的 `KeyGenerationParameters`。
    Basic { strength: usize },
    #[cfg(feature = "rc2")]
    Rc2 {
        strength: usize,
        effective_key_bits: usize,
    },
    #[cfg(feature = "rc5")]
    Rc5 { strength: usize, rounds: usize },
    /// RSA 的公開指數、模數長度（bits）與質數檢測的 certainty，對應 BC 的 `RsaKeyGenerationParameters`。
    #[cfg(feature = "rsa")]
    Rsa {
        public_exponent: u32,
        strength: usize,
        certainty: u32,
    },
    /// EC 的曲線，對應 BC 的 `ECKeyGenerationParameters`。EC 只收這個：曲線一定要明確指定。
    #[cfg(feature = "ec")]
    Ec { curve: crate::params::EcCurve },
}

impl KeyGenParams {
    #[cfg(any(
        feature = "aes",
        feature = "ascon",
        feature = "camellia",
        feature = "chacha",
        feature = "rc2",
        feature = "rc5",
        feature = "rsa"
    ))]
    pub(crate) fn strength(&self) -> usize {
        match *self {
            Self::Basic { strength } => strength,
            #[cfg(feature = "rc2")]
            Self::Rc2 { strength, .. } => strength,
            #[cfg(feature = "rc5")]
            Self::Rc5 { strength, .. } => strength,
            #[cfg(feature = "rsa")]
            Self::Rsa { strength, .. } => strength,
            // 用長度的產生器在 check_params 就拒絕了 Ec，走不到這裡
            #[cfg(feature = "ec")]
            Self::Ec { .. } => 0,
        }
    }
}
