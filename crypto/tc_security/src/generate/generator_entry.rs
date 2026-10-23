use rand::CryptoRng;
use tc_asn1::NamedOid;

use super::{Generator, KeyGenParams};
use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

type CheckParams = fn(&KeyGenParams) -> Result<(), SecurityError>;
type GenerateKey = fn(&KeyGenParams, &mut dyn CryptoRng) -> Result<AnyParams, SecurityError>;
type GenerateKeyPair =
    fn(&KeyGenParams, &mut dyn CryptoRng) -> Result<(AnyParams, AnyParams), AnyError>;

/// 產生器表的一列：名稱、別名、OID、預設參數與產生函式，由它建立 [`Generator`]。
#[derive(Clone, Copy, Debug)]
pub struct GeneratorEntry {
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    default_params: Option<KeyGenParams>,
    check_params: CheckParams,
    generate_key: GenerateKey,
    generate_key_pair: GenerateKeyPair,
}

impl GeneratorEntry {
    #[allow(dead_code, reason = "所有演算法的 feature 都關掉時，表是空的")]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        default_params: KeyGenParams,
        check_params: CheckParams,
        generate_key: GenerateKey,
        generate_key_pair: GenerateKeyPair,
    ) -> Self {
        Self {
            names,
            oids,
            default_params: Some(default_params),
            check_params,
            generate_key,
            generate_key_pair,
        }
    }

    /// 沒有預設參數的產生器：一定要先呼叫 `init`，例如 EC 要指定曲線。
    #[allow(dead_code, reason = "ec 的 feature 關掉時沒用到")]
    pub(super) const fn without_default(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        check_params: CheckParams,
        generate_key: GenerateKey,
        generate_key_pair: GenerateKeyPair,
    ) -> Self {
        Self {
            names,
            oids,
            default_params: None,
            check_params,
            generate_key,
            generate_key_pair,
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

    pub(super) fn generate_key(
        &self,
        params: &KeyGenParams,
        rng: &mut dyn CryptoRng,
    ) -> Result<AnyParams, SecurityError> {
        (self.generate_key)(params, rng)
    }

    pub(super) fn generate_key_pair(
        &self,
        params: &KeyGenParams,
        rng: &mut dyn CryptoRng,
    ) -> Result<(AnyParams, AnyParams), AnyError> {
        (self.generate_key_pair)(params, rng)
    }

    /// 預設的金鑰長度（bits），同 BC 的 `GeneratorUtilities.GetDefaultKeySize`；沒有預設參數或不是
    /// 只有長度的參數時回傳 `None`。
    #[cfg(feature = "pbe")]
    pub(crate) fn default_strength(&self) -> Option<usize> {
        match self.default_params {
            Some(KeyGenParams::Basic { strength }) => Some(strength),
            _ => None,
        }
    }

    /// 建立一個新的產生器，還沒呼叫 `init` 時用這一列的預設參數；沒有預設參數的要先 `init`。
    pub fn generator(&'static self) -> Generator {
        Generator::new(self, self.default_params)
    }
}
