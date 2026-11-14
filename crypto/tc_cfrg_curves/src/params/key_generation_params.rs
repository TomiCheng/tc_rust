/// BC 的 `KeyGenerationParameters`，不含亂數來源：亂數來源在產生器建構時給。
/// CFRG 曲線的金鑰長度固定，所以沒有欄位。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyGenerationParams;

impl KeyGenerationParams {
    pub const fn new() -> Self {
        Self
    }
}
