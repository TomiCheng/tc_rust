//! 編碼規則。

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingType {
    /// 不排序、不正規化。長度一律寫定長（合法的 BER）。
    Ber,
    /// 一個值只有一種編碼。
    Der,
}
