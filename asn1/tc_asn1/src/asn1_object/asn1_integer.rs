//! ASN.1 `INTEGER`。

use alloc::vec::Vec;

/// 一個 ASN.1 `INTEGER`。
pub struct Asn1Integer {
    content: Content,
}

enum Content {
    U128(u128),
    I128(i128),
    BigValue(Vec<u8>),
}
