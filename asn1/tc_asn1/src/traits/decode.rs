//! 讀入的契約。

use crate::depth::Depth;

/// 能從 ASN.1 編碼還原的值。
///
/// # 只有一套解碼
///
/// 解碼一律照 BER —— 它是三種規則的超集。這和 [`TryEncode`] 收
/// `EncodingType` 不對稱，而且是刻意的：編碼時同一個值有多種寫法所以要選，
/// 解碼時讀進來的位元組只有一種讀法。
///
/// [`TryEncode`]: crate::TryEncode
///
/// 需要「輸入必須是 DER」的地方（憑證鏈驗證是典型），用往返比較檢查：把解出
/// 來的值照 [`EncodingType::Der`] 重編，和原位元組相等才是 DER。這個檢查成立
/// 是因為 DER 的定義就是「一個值只有一種合法編碼」，不需要第二個嚴格解碼器。
///
/// [`EncodingType::Der`]: crate::EncodingType::Der
///
/// # 驗簽章要用原始位元組
///
/// 寬鬆解碼會把非 DER 的輸入正規化，重新編碼後位元組不同，雜湊就對不上。
/// 簽章蓋在進來的那份位元組上，就要拿那份去驗 —— 這是寬鬆解碼唯一真正危險的
/// 誤用方式。
///
/// # 巢狀深度
///
/// 解碼是遞迴的，而 constructed 型別可以無限往下巢狀 —— 沒有上限的話一段刻意
/// 構造的輸入就能耗盡堆疊。[`Depth`] 是還能再走幾層的預算。
///
/// 一層巢狀就是一次 [`Asn1Object`] 的解碼，所以**預算由 `Asn1Object` 的實作消耗**，
/// constructed 型別把剩下的傳給子元素。葉節點收得到 `depth` 但用不到它 ——
/// 它們不會遞迴。
///
/// 這樣每層剛好扣一次。如果每個型別都自己扣，`Asn1Object` 加上被包住的型別
/// 會讓同一層扣兩次。
///
/// [`Asn1Object`]: crate::Asn1Object
///
/// # 時間性質
///
/// 變動時間：分支依編碼結構與長度，不檢視內容位元組的值。
pub trait TryDecode: Sized {
    /// 解碼失敗的原因。
    type Error: core::error::Error;

    /// 變動時間：從 `buff` 前端解出一個值，回傳消耗的位元組數與該值。
    ///
    /// 尾端剩下的位元組不算錯誤 —— 巢狀結構本來就是一個接一個解，
    /// 由呼叫端依消耗長度決定是否還有東西要讀。
    ///
    /// `depth` 是剩餘的巢狀預算，用完回 [`Asn1Error::DepthExceeded`]。
    ///
    /// [`Asn1Error::DepthExceeded`]: crate::Asn1Error::DepthExceeded
    fn try_decode(buff: &[u8], depth: Depth) -> Result<(usize, Self), Self::Error>;
}
