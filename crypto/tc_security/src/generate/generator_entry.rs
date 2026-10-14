use tc_asn1::NamedOid;

use super::{Generator, KeyGenParams};
use crate::SecurityError;

/// 產生器表的一列：名稱、別名、OID 與預設參數，由它建立 [`Generator`]。
#[derive(Clone, Copy, Debug)]
pub struct GeneratorEntry {
    // 第一個是正式名稱，其餘是別名
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    // 沒呼叫 init 時用的參數
    default_params: KeyGenParams,
    // init 收到的參數：檢查是不是這個演算法接受的，必要時換成它自己的 variant
    check_params: fn(&KeyGenParams) -> Result<KeyGenParams, SecurityError>,
}

impl GeneratorEntry {
    #[allow(dead_code, reason = "所有演算法的 feature 都關掉時，表是空的")]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        default_params: KeyGenParams,
        check_params: fn(&KeyGenParams) -> Result<KeyGenParams, SecurityError>,
    ) -> Self {
        Self {
            names,
            oids,
            default_params,
            check_params,
        }
    }

    /// 正式名稱，例如 `"AES"`。
    pub fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub(super) fn check_params(
        &self,
        params: &KeyGenParams,
    ) -> Result<KeyGenParams, SecurityError> {
        (self.check_params)(params)
    }

    /// 建立一個新的產生器，還沒呼叫 `init` 時用這一列的預設參數。
    pub fn generator(&'static self) -> Generator {
        Generator::new(self, self.default_params)
    }
}
