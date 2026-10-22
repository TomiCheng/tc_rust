use core::fmt::{self, Display, Formatter};
use core::hash::{Hash, Hasher};

use tc_asn1::NamedOid;
use tc_digest::Digest;

use super::{Algorithm, AnyDigest};

#[derive(Clone, Copy, Debug)]
pub struct DigestEntry {
    algorithm: Algorithm,
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    // 第一個是 digest 本身的 OID，其餘照 BC 也對到這一列
    oids: &'static [NamedOid],
    constructor: fn() -> Box<dyn Digest>,
}

impl DigestEntry {
    #[allow(dead_code, reason = "所有 digest 的 feature 都關掉時，表是空的")]
    pub(super) const fn new(
        algorithm: Algorithm,
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        constructor: fn() -> Box<dyn Digest>,
    ) -> Self {
        Self {
            algorithm,
            names,
            oids,
            constructor,
        }
    }

    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// 正式名稱，例如 `"SHA-256"`。
    pub const fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) const fn names(&self) -> &'static [&'static str] {
        self.names
    }

    /// digest 本身的 OID，DigestInfo 用的就是它；原始 Keccak 沒有。
    pub fn oid(&self) -> Option<NamedOid> {
        self.oids.first().copied()
    }

    /// 對到這一列的所有 OID，第一個是 digest 本身的。
    pub const fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub fn create(&'static self) -> AnyDigest {
        AnyDigest {
            entry: self,
            digest: (self.constructor)(),
        }
    }
}

// 一個演算法在表裡只有一列，所以只比 algorithm；函式指標的比較結果不可靠
impl PartialEq for DigestEntry {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
    }
}

impl Eq for DigestEntry {}

impl Hash for DigestEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
    }
}

/// 正式名稱，有 OID 時接在後面，例如 `SHA-256  [id-sha256, id-hmacWithSHA256]`。
impl Display for DigestEntry {
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
