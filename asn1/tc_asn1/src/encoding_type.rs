//! 編碼規則。

/// 一份 ASN.1 值可以照哪一套規則編碼。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingType {
    /// 基本編碼規則。允許不定長度、非最短長度、字串分段、`SET` 不排序。
    Ber,
    /// 可辨別編碼規則。同一個值只有一種合法編碼。
    Der,
    /// 定長編碼。長度一律定長，但不做 `Der` 的正規化。
    Dl,
}
