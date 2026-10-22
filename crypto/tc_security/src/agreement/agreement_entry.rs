use std::fmt::{self, Display, Formatter};

use tc_asn1::NamedOid;

use super::AnyAgreement;

/// 一種 key agreement 演算法。
#[derive(Clone, Copy, Debug)]
pub struct AgreementEntry {
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    agreement: fn() -> AnyAgreement,
}

impl AgreementEntry {
    #[allow(dead_code, reason = "所有 agreement 的 feature 都關掉時，表是空的")]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        agreement: fn() -> AnyAgreement,
    ) -> Self {
        Self {
            names,
            oids,
            agreement,
        }
    }

    /// 正式名稱，例如 `"X25519"`。
    pub fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    /// 建立一個還沒初始化的 agreement。
    pub fn agreement(&self) -> AnyAgreement {
        (self.agreement)()
    }
}

/// 正式名稱，有 OID 時接在後面，例如 `X25519  [id-X25519]`。
impl Display for AgreementEntry {
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
