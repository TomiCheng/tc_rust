use rand_core::CryptoRng;

/// BC 的 `DsaParameterGenerationParameters`：FIPS 186-3 的 p 位元數 L、q 位元數 N、質數檢定
/// 的 certainty 與亂數來源；有用途索引時，g 照 FIPS 186-3 A.2.3 可驗證地產生。只是容器，
/// 產生器的 `init` 才檢查。
pub struct DsaParameterGenerationParams<'a> {
    pub(crate) l: u32,
    pub(crate) n: u32,
    pub(crate) certainty: u32,
    pub(crate) rng: &'a mut dyn CryptoRng,
    pub(crate) usage_index: Option<u8>,
}

impl<'a> DsaParameterGenerationParams<'a> {
    /// BC 的 `DigitalSignatureUsage`。
    pub const DIGITAL_SIGNATURE_USAGE: u8 = 1;
    /// BC 的 `KeyEstablishmentUsage`。
    pub const KEY_ESTABLISHMENT_USAGE: u8 = 2;

    /// 沒有用途索引：g 以亂數產生。常數時間。
    pub fn new(l: u32, n: u32, certainty: u32, rng: &'a mut dyn CryptoRng) -> Self {
        Self {
            l,
            n,
            certainty,
            rng,
            usage_index: None,
        }
    }

    /// 設定用途索引，g 改為可驗證地產生。常數時間。
    pub fn with_usage_index(mut self, usage_index: u8) -> Self {
        self.usage_index = Some(usage_index);
        self
    }

    /// L。常數時間。
    pub fn l(&self) -> u32 {
        self.l
    }

    /// N。常數時間。
    pub fn n(&self) -> u32 {
        self.n
    }

    /// certainty。常數時間。
    pub fn certainty(&self) -> u32 {
        self.certainty
    }

    /// 用途索引。常數時間。
    pub fn usage_index(&self) -> Option<u8> {
        self.usage_index
    }
}
