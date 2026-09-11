//! INTEGER 與 ENUMERATED 共用的二補數內容規則，不持有值也不配置。

use crate::error::Asn1Error;

/// 驗證非空且沒有多餘的符號位元組；變動時間，依內容長度與符號位元組分支。
pub(crate) fn validate_integer_octets(bytes: &[u8]) -> Result<(), Asn1Error> {
    match bytes {
        [] => Err(Asn1Error::MalformedValue),
        // 多餘的符號位元組（X.690 8.3.2），BER 也禁止。
        [0x00, next, ..] if next & 0x80 == 0 => Err(Asn1Error::MalformedValue),
        [0xFF, next, ..] if next & 0x80 != 0 => Err(Asn1Error::MalformedValue),
        _ => Ok(()),
    }
}

/// 去掉固定寬度二補數中多餘的符號位元組；變動時間，依符號延伸量分支。
/// 輸入非空時至少保留一個位元組，空切片則原樣回傳。
pub(crate) fn minimal_signed(mut bytes: &[u8]) -> &[u8] {
    while let [first, next, ..] = bytes {
        let redundant =
            (*first == 0x00 && next & 0x80 == 0) || (*first == 0xFF && next & 0x80 != 0);
        if !redundant {
            break;
        }
        bytes = &bytes[1..];
    }
    bytes
}
