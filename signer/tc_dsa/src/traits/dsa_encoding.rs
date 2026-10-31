use crate::DsaEncodingError;
use tc_bigint::PaddedBigUint;

/// BC 的 `IDsaEncoding`：把 DSA 簽章 (r, s) 編成位元組或解回來，r 與 s 都要在 `[0, n)` 裡，
/// n 是群的階。簽章是公開的，所以實作都是變動時間。
pub trait DsaEncoding {
    /// 階為 `order` 時，編碼最多佔的位元組數。變動時間：只能用於公開值。
    fn max_encoding_size(&self, order: &PaddedBigUint) -> usize;

    /// 把 (r, s) 寫進 `output` 的前段並回傳長度。變動時間：只能用於公開值。
    fn encode(
        &self,
        order: &PaddedBigUint,
        r: &PaddedBigUint,
        s: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<usize, DsaEncodingError>;

    /// 解出 (r, s)。變動時間：只能用於公開值。
    fn decode(
        &self,
        order: &PaddedBigUint,
        encoding: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaEncodingError>;
}
