use rand_core::CryptoRng;

use crate::{EcdsaScalar, KCalculator};

/// 使用呼叫端亂數來源取樣 ECDSA 暫時純量。
pub struct RandomKCalculator<'a, S, R: ?Sized> {
    n: S,
    rng: &'a mut R,
}

impl<'a, S: EcdsaScalar, R: CryptoRng + ?Sized> RandomKCalculator<'a, S, R> {
    /// 綁定公開的群階與外部密碼學亂數來源。
    pub fn new(n: &S, rng: &'a mut R) -> Self {
        Self { n: *n, rng }
    }
}

impl<S: EcdsaScalar, R: CryptoRng + ?Sized> KCalculator<S> for RandomKCalculator<'_, S, R> {
    fn is_deterministic(&self) -> bool {
        false
    }

    fn next_k(&mut self) -> S {
        S::random_nonzero_below(self.rng, &self.n)
    }
}
