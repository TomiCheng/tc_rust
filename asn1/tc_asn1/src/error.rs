//! 解析與編碼的失敗原因。

use core::fmt;

/// ASN.1 解析或編碼失敗的原因。
///
/// 每個變體對應一個具體缺陷，不做「無效編碼」這種籠統歸類 —— 拒絕的理由本身
/// 是有用的診斷資訊，尤其在對接別家實作時。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Asn1Error {
    /// 輸入在一個 TLV 中途結束。
    Truncated,

    /// 一個完整的值之後還有位元組。
    TrailingData,

    /// tag 號碼使用了非最短的高號碼形式。
    NonMinimalTag,

    /// tag 號碼大於本實作支援的上限。
    TagOverflow,

    /// 長度大於本平台的 `usize` 所能表示。
    LengthOverflow,

    /// 讀到的 tag 不是這個位置預期的型別。
    UnexpectedTag,

    /// 內容位元組不符合該型別的規則。
    MalformedValue,

    /// 數值無法精確表示於目標型別；不進行捨入、溢位或下溢轉換。
    InexactValue,

    /// 巢狀比允許的深度更深。
    DepthExceeded,

    /// 呼叫端提供的輸出緩衝不足。
    BufferTooSmall,
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Truncated => "input ended inside a TLV",
            Self::TrailingData => "unexpected bytes after the encoded value",
            Self::NonMinimalTag => "tag number is not in the shortest form",
            Self::TagOverflow => "tag number exceeds the supported range",
            Self::LengthOverflow => "length exceeds the platform's usize",
            Self::UnexpectedTag => "tag does not match the expected type",
            Self::MalformedValue => "contents are not valid for this type",
            Self::InexactValue => "value cannot be represented exactly by the target type",
            Self::DepthExceeded => "nesting is deeper than the allowed limit",
            Self::BufferTooSmall => "output buffer is too small",
        })
    }
}

impl core::error::Error for Asn1Error {}
