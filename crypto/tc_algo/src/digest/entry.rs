use core::fmt;
use core::hash::{Hash, Hasher};

use tc_asn1::NamedOid;

use super::dyn_digest::DynDigest;
use super::{Algorithm, AnyDigest};

#[derive(Clone, Copy, Debug)]
pub struct DigestEntry {
    algorithm: Algorithm,
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    // 第一個是 digest 本身的 OID，其餘照 BC 也對到這一列
    oids: &'static [NamedOid],
    constructor: fn() -> Box<dyn DynDigest>,
}

impl DigestEntry {
    pub fn algorithm(&self) -> Algorithm {
        todo!()
    }

    pub fn name(&self) -> &'static str {
        todo!()
    }

    pub fn oid(&self) -> Option<NamedOid> {
        todo!()
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        todo!()
    }

    pub fn create(&'static self) -> AnyDigest {
        todo!()
    }
}

impl PartialEq for DigestEntry {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl Eq for DigestEntry {}

impl Hash for DigestEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        todo!()
    }
}

impl fmt::Display for DigestEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
