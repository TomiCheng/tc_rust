mod sealed {
    pub trait Sealed {}
}

/// CTS 底下的串接方式：[`Ecb`] 或 [`Cbc`]，決定 `init` 要不要 IV。
pub trait CtsChaining: sealed::Sealed {
    #[doc(hidden)]
    const CBC: bool;
}

/// 不串接，同 BC 以 `EcbBlockCipher` 建構的 `CtsBlockCipher`。`init` 的參數直接交給
/// block cipher。
pub struct Ecb;

/// CBC 串接，同 BC 以 `CbcBlockCipher` 建構的 `CtsBlockCipher`。超過一個區塊時就是
/// RFC 3962 的 CBC-CTS（NIST SP 800-38A 附錄的 CS3）；剛好一個區塊時，BC 會把加密後的
/// 區塊再加密一次，這裡照做。`init` 的參數要提供一個區塊長的 IV。
pub struct Cbc;

impl sealed::Sealed for Ecb {}
impl sealed::Sealed for Cbc {}

impl CtsChaining for Ecb {
    const CBC: bool = false;
}

impl CtsChaining for Cbc {
    const CBC: bool = true;
}
