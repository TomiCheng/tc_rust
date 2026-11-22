//! DRBG 的共用介面。

use rand_core::CryptoRng;

use crate::DrbgError;

/// NIST SP 800-90A DRBG 的共用操作。
pub trait Drbg {
    /// 產生隨機位元組，並可混入額外輸入。
    ///
    /// # Errors
    ///
    /// - `output` 超過 32 KiB（2^18 bits）時回傳 [`DrbgError::RequestTooLarge`]。
    ///   需要更多時分次呼叫。
    /// - 自上次植入起已有 2^47 次請求時回傳 [`DrbgError::ReseedRequired`]，之後
    ///   每次都失敗，直到呼叫 [`Drbg::reseed`]。本 crate 不持有熵來源，不會自動
    ///   重新植入。每次 `generate`、`try_fill_bytes`、`try_next_u32`、`try_next_u64`
    ///   都算一次請求，與長度無關；`reseed` 把計數歸零。要避免這個錯誤，自行計數並
    ///   在上限前呼叫 `reseed`，或定期（例如每產生一把金鑰）呼叫。
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
