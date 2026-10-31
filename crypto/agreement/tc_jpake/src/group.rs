use crate::JPakeError;
use rand_core::CryptoRng;
use tc_bigint::{BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};
use tc_prime::Primality;

// BC 以 certainty 20 呼叫 `IsProbablePrime`，也就是 10 輪 Miller-Rabin。
const MILLER_RABIN_ROUNDS: u32 = 10;

/// BC 的 `JPakePrimeOrderGroup`：質數 p、整除 p − 1 的質數 q，與 q 階的生成元 g。
///
/// 只是容器，建構時不檢查；[`validate`](Self::validate) 做 BC 建構子的檢查，由
/// `JPakeParticipant::init` 呼叫。[`standard_groups`](crate::standard_groups) 的群組同
/// BC 略過檢查。
#[derive(Clone, Debug)]
pub struct JPakePrimeOrderGroup {
    p: PaddedBigUint,
    q: PaddedBigUint,
    g: PaddedBigUint,
    skip_checks: bool,
}

impl JPakePrimeOrderGroup {
    /// 包起 p、q、g，不檢查。常數時間。
    pub fn new(p: PaddedBigUint, q: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            p,
            q,
            g,
            skip_checks: false,
        }
    }

    /// 已知正確、`validate` 不必檢查的群組，BC 的 `skipChecks`。常數時間。
    pub(crate) fn trusted(p: PaddedBigUint, q: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            skip_checks: true,
            ..Self::new(p, q, g)
        }
    }

    /// 模數 p。常數時間。
    pub fn p(&self) -> &PaddedBigUint {
        &self.p
    }

    /// 子群的階 q。常數時間。
    pub fn q(&self) -> &PaddedBigUint {
        &self.q
    }

    /// 生成元 g。常數時間。
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// BC 建構子的檢查，依序是：q 整除 p − 1、g 在 `[2, p − 1]`、g^q mod p 為 1、p 與 q
    /// 各通過 10 輪 Miller-Rabin（BC 的 certainty 20）。另外要求 q 是奇數，Montgomery 運算
    /// 需要；BC 接受 q = 2。標準群組同 BC 不檢查。變動時間：只用於公開值。
    pub fn validate<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<(), JPakeError> {
        if self.skip_checks {
            return Ok(());
        }
        let zero = BigUint::from(0u8);
        let one = BigUint::from(1u8);
        let p = BigUint::from(self.p.clone());
        let q = BigUint::from(self.q.clone());
        let g = BigUint::from(self.g.clone());
        if q == zero {
            return Err(JPakeError::OrderNotPrime);
        }
        if p == zero {
            return Err(JPakeError::ModulusNotPrime);
        }
        if (&p - 1u32) % &q != zero {
            return Err(JPakeError::OrderNotDividing);
        }
        if g < BigUint::from(2u8) || g >= p {
            return Err(JPakeError::GeneratorOutOfRange);
        }
        let modulus = NonZero::new(p.clone()).expect("p is above g");
        if g.mod_pow(&q, &modulus) != one {
            return Err(JPakeError::GeneratorOrderMismatch);
        }
        if !p.is_probable_prime(MILLER_RABIN_ROUNDS, rng) {
            return Err(JPakeError::ModulusNotPrime);
        }
        if !q.bit(0) || !q.is_probable_prime(MILLER_RABIN_ROUNDS, rng) {
            return Err(JPakeError::OrderNotPrime);
        }
        Ok(())
    }
}
