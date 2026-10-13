use std::fmt::{self, Display, Formatter};

use tc_asn1::NamedOid;

use super::AnyWrapper;

/// 一種 key wrap 演算法。
#[derive(Clone, Copy, Debug)]
pub struct WrapEntry {
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    // 可接受的金鑰（KEK）長度，以及產生金鑰時的長度，以 byte 計
    #[allow(dead_code, reason = "產生金鑰的 generator 模組會讀")]
    key_sizes: &'static [usize],
    #[allow(dead_code, reason = "產生金鑰的 generator 模組會讀")]
    default_key_size: usize,
    wrapper: fn() -> AnyWrapper,
}

impl WrapEntry {
    #[allow(dead_code, reason = "所有 wrapper 的 feature 都關掉時，表是空的")]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        key_sizes: &'static [usize],
        default_key_size: usize,
        wrapper: fn() -> AnyWrapper,
    ) -> Self {
        Self {
            names,
            oids,
            key_sizes,
            default_key_size,
            wrapper,
        }
    }
    /// 正式名稱，例如 `"AESWRAP"`。
    pub fn name(&self) -> &'static str {
        self.names[0]
    }
    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }
    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }
    pub fn wrapper(&self) -> AnyWrapper {
        (self.wrapper)()
    }
}

/// 正式名稱，有 OID 時接在後面，例如
/// `AESWRAP  [id-aes128-wrap, id-aes192-wrap, id-aes256-wrap]`。
impl Display for WrapEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        if let Some((first, rest)) = self.oids.split_first() {
            write!(f, "  [{}", first.name())?;
            for oid in rest {
                write!(f, ", {}", oid.name())?;
            }
            f.write_str("]")?;
        }
        Ok(())
    }
}
