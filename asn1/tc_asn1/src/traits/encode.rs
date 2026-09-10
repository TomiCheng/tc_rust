//! 寫出的契約。

use crate::encoding_type::EncodingType;

/// 能寫成 ASN.1 編碼的值。
///
/// # 實作者契約
///
/// 同一個 `encoding_type` 下，[`Self::try_encode`] 寫出的位元組數必須等於
/// [`Self::try_encode_len`] 回報的數字。兩者漂移會產生損毀的輸出，而且錯誤會
/// 出現在離成因很遠的地方 —— 通常是外層某個 SEQUENCE 的長度對不上內容。
/// 每個實作都要有測試釘住這一點。
///
/// # 時間性質
///
/// 兩個方法都是**變動時間**，分支只依編碼結構，不檢視內容位元組的值。
///
/// 但編碼長度本身會隨值改變（INTEGER 的最小編碼規則就是如此），所以編碼一個
/// 秘密值必然從長度洩漏它的大小。這是 X.690 的性質，換任何實作都一樣，
/// 只能揭露不能避免。
pub trait TryEncode {
    /// 編碼失敗的原因。
    type Error: core::error::Error;

    /// 變動時間：回報照 `encoding_type` 編碼後的位元組數，含 tag 與長度。
    ///
    /// 呼叫端用它決定緩衝大小。長度隨規則改變 —— 例如不定長度的表頭是一個
    /// 位元組加結尾的兩個位元組，定長則是一到數個位元組。
    fn try_encode_len(&self, encoding_type: EncodingType) -> Result<usize, Self::Error>;

    /// 變動時間：照 `encoding_type` 把編碼寫進 `buff` 前端，回傳寫入的位元組數。
    ///
    /// `buff` 短於 [`Self::try_encode_len`] 回報的長度時回錯誤，
    /// 此時不保證 `buff` 的內容。
    fn try_encode(
        &self,
        encoding_type: EncodingType,
        buff: &mut [u8],
    ) -> Result<usize, Self::Error>;
}
