/// 產生金鑰的參數，對應 BC 的 `KeyGenerationParameters` 與它的子類別。
///
/// 只是 DTO，不驗證內容：數值合不合用，由產生器在 `init` 判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyGenParams {
    /// 只有長度（bits），對應 BC 的 `KeyGenerationParameters`。
    Basic { strength: usize },
    /// RSA 的公開指數、模數長度（bits）與質數檢測的 certainty，對應 BC 的 `RsaKeyGenerationParameters`。
    #[cfg(feature = "rc2")]
    Rc2 {
        strength: usize,
        effective_key_bits: usize,
    },
    #[cfg(feature = "rsa")]
    Rsa {
        public_exponent: u32,
        strength: usize,
        certainty: u32,
    },
}
