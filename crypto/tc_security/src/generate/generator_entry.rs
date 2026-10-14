use rand::CryptoRng;
use tc_asn1::NamedOid;

use super::{Generator, KeyGenParams};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

type GenerateKey = fn(&KeyGenParams, &mut dyn CryptoRng) -> AnyParams;
type GenerateKeyPair =
    fn(&KeyGenParams, &mut dyn CryptoRng) -> Result<(AnyParams, AnyParams), AnyError>;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code, reason = "只開對稱或只開非對稱演算法時，另一種用不到")]
pub(super) enum Generate {
    Key(GenerateKey),
    KeyPair(GenerateKeyPair),
}

/// 產生器表的一列：名稱、別名、OID、預設參數與產生方式，由它建立 [`Generator`]。
#[derive(Clone, Copy, Debug)]
pub struct GeneratorEntry {
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    default_params: KeyGenParams,
    check_params: fn(&KeyGenParams) -> Result<(), SecurityError>,
    generate: Generate,
}

impl GeneratorEntry {
    #[allow(dead_code, reason = "所有演算法的 feature 都關掉時，表是空的")]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        default_params: KeyGenParams,
        check_params: fn(&KeyGenParams) -> Result<(), SecurityError>,
        generate: Generate,
    ) -> Self {
        Self {
            names,
            oids,
            default_params,
            check_params,
            generate,
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

    pub(super) fn check_params(&self, params: &KeyGenParams) -> Result<(), SecurityError> {
        (self.check_params)(params)
    }

    pub(super) fn generate(&self) -> Generate {
        self.generate
    }

    /// 建立一個新的產生器，還沒呼叫 `init` 時用這一列的預設參數。
    pub fn generator(&'static self) -> Generator {
        Generator::new(self, self.default_params)
    }
}
