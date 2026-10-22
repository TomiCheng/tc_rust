use std::fmt::{self, Display, Formatter};

use tc_asn1::NamedOid;

use super::AnySigner;

/// 一種簽章演算法。
#[derive(Clone, Copy, Debug)]
pub struct SignerEntry {
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    signer: fn() -> AnySigner,
}

impl SignerEntry {
    #[allow(dead_code, reason = "所有 signer 的 feature 都關掉時，表是空的")]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        signer: fn() -> AnySigner,
    ) -> Self {
        Self {
            names,
            oids,
            signer,
        }
    }

    /// 正式名稱，例如 `"SHA-256withRSA"`。
    pub fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    /// 建立一個還沒初始化的簽章器。
    pub fn signer(&self) -> AnySigner {
        (self.signer)()
    }
}

/// 正式名稱，有 OID 時接在後面，例如 `SHA-256withRSA  [sha256WithRSAEncryption]`。
impl Display for SignerEntry {
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
