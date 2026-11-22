//! DRBG 的共用介面。

use rand_core::CryptoRng;

use crate::DrbgError;

/// NIST SP 800-90A DRBG 的共用操作。
pub trait Drbg {
    /// 產生隨機位元組，並可混入額外輸入。
    ///
    /// 超過重新植入上限時回傳 [`DrbgError::ReseedRequired`]；`output` 超過 32 KiB
    /// 時回傳 [`DrbgError::RequestTooLarge`]。
    fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError>;

    /// 從呼叫端提供的密碼學安全亂數來源重新植入狀態。
    ///
    /// # Errors
    ///
    /// 底層密碼原語失敗，或無 derivation function 的 CTR_DRBG 收到長度不符的
    /// 種子材料時回傳錯誤。此時內部狀態可能已部分更新，不應再用它產生輸出。
    fn reseed<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError>;
}
