use std::io;

use crate::PemObject;

/// 把 PEM 物件轉成其他型別，對應 BC 的 `PemObjectParser`。BC 回傳 `object`，
/// 這裡改用關聯型別。
pub trait PemObjectParser {
    type Output;

    /// 解析 `obj`。實作要標明常數時間或變動時間。
    fn parse_object(&self, obj: &PemObject) -> io::Result<Self::Output>;
}
