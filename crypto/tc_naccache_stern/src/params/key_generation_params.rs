
/// BC 的 `NaccacheSternKeyGenerationParameters` ，不含亂數來源（產生器建構時給）：n 的位元數（強度）、質數檢定的
/// certainty 與小質數的個數。只是容器，產生器的 `init` 才檢查；BC 在建構時檢查小質數的
/// 個數。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NaccacheSternKeyGenerationParams {
    pub(crate) strength: u32,
    pub(crate) certainty: u32,
    pub(crate) count_small_primes: usize,
}

impl NaccacheSternKeyGenerationParams {
    /// 包起各值，不檢查。常數時間。
    pub fn new(
        strength: u32,
        certainty: u32,
        count_small_primes: usize,
    ) -> Self {
        Self {
            strength,
            certainty,
            count_small_primes,
        }
    }

    /// n 的位元數。常數時間。
    pub fn strength(&self) -> u32 {
        self.strength
    }

    /// 質數檢定的 certainty。常數時間。
    pub fn certainty(&self) -> u32 {
        self.certainty
    }

    /// 小質數的個數。常數時間。
    pub fn count_small_primes(&self) -> usize {
        self.count_small_primes
    }
}
