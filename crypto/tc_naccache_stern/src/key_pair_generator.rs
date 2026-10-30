use crate::small_primes::SMALL_PRIMES;
use crate::{
    NaccacheSternError, NaccacheSternKeyGenerationParams, NaccacheSternPrivateKey,
    NaccacheSternPublicKey,
};
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};
use tc_prime::Primality;

/// BC 的 `NaccacheSternKeyPairGenerator`。
///
/// 產生金鑰是變動時間：大數以 `BigUint` 計算，質數搜尋、取冪與比較都依秘密的值分支，
/// 同 `tc_rsa` 產生金鑰時的取捨。產生的金鑰本身與加解密的時間性無關。
pub struct NaccacheSternKeyPairGenerator<'a> {
    params: Option<NaccacheSternKeyGenerationParams<'a>>,
}

impl NaccacheSternKeyPairGenerator<'_> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl Default for NaccacheSternKeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<NaccacheSternKeyGenerationParams<'a>>
    for NaccacheSternKeyPairGenerator<'a>
{
    type Error = NaccacheSternError;

    /// BC 建構參數時的檢查：小質數的個數是 30 以上的偶數，且不超過內建的質數表；另外
    /// 檢查 certainty 至少為 1，以及強度扣掉 σ 與 48 位元後還放得下 p、q 的大質因數，
    /// BC 要到產生時才失敗。變動時間：參數是公開值。
    fn init(
        &mut self,
        params: NaccacheSternKeyGenerationParams<'a>,
    ) -> Result<(), NaccacheSternError> {
        self.params = None;
        let count = params.count_small_primes;
        if count % 2 == 1 || count < 30 || count > SMALL_PRIMES.len() {
            return Err(NaccacheSternError::InvalidSmallPrimeCount);
        }
        if params.certainty == 0 {
            return Err(NaccacheSternError::InvalidCertainty);
        }
        let sigma = SMALL_PRIMES[..count]
            .iter()
            .fold(BigUint::from(1u8), |sigma, &p| sigma * BigUint::from(p));
        if remaining_strength(params.strength, &sigma) / 2 + 1 < 2 {
            return Err(NaccacheSternError::StrengthTooSmall);
        }
        self.params = Some(params);
        Ok(())
    }
}

impl KeyPairGenerator for NaccacheSternKeyPairGenerator<'_> {
    type PublicKey = NaccacheSternPublicKey;
    type PrivateKey = NaccacheSternPrivateKey;
    type Error = NaccacheSternError;

    /// BC 的 `GenerateKeyPair`：打亂前 k 個小質數，前半乘成 u、後半乘成 v，σ = u·v；
    /// p = 2·a·u·p′ + 1、q = 2·b·v·q′ + 1，a、b 是大質數，p′、q′ 是 24 位元的質數；再找出
    /// 階為 φ(n) / 4 的 g。變動時間，見型別說明。
    fn generate_key_pair(
        &mut self,
    ) -> Result<(NaccacheSternPublicKey, NaccacheSternPrivateKey), NaccacheSternError> {
        let params = self
            .params
            .as_mut()
            .ok_or(NaccacheSternError::NotInitialized)?;
        let (strength, certainty) = (params.strength, params.certainty);
        let rng = &mut *params.rng;

        let primes = permute(&SMALL_PRIMES[..params.count_small_primes], rng);
        let half = primes.len() / 2;
        let product = |list: &[u32]| {
            list.iter()
                .fold(BigUint::from(1u8), |acc, &p| acc * BigUint::from(p))
        };
        let (u, v) = (product(&primes[..half]), product(&primes[half..]));
        let sigma = &u * &v;

        let remaining = remaining_strength(strength, &sigma);
        let a = random_prime(rng, (remaining / 2 + 1) as u32, certainty);
        let b = random_prime(rng, (remaining / 2 + 1) as u32, certainty);
        let two_au = (&a * &u) << 1;
        let two_bv = (&b * &v) << 1;

        let (p_prime, q_prime, p, q, n) = loop {
            let p_prime = random_prime(rng, 24, certainty);
            let p = &p_prime * &two_au + 1u32;
            if !p.is_probable_prime(rounds(certainty, p.bits()), rng) {
                continue;
            }
            let (q_prime, q) = loop {
                let q_prime = random_prime(rng, 24, certainty);
                if q_prime == p_prime {
                    continue;
                }
                let q = &q_prime * &two_bv + 1u32;
                if q.is_probable_prime(rounds(certainty, q.bits()), rng) {
                    break (q_prime, q);
                }
            };
            if (&p_prime * &q_prime).gcd(&sigma) != BigUint::from(1u8) {
                continue;
            }
            let n = &p * &q;
            if n.bits() >= strength {
                break (p_prime, q_prime, p, q, n);
            }
        };

        let phi = (&p - 1u32) * (&q - 1u32);
        let modulus = NonZero::new(n.clone()).expect("n is a product of primes");
        let one = BigUint::from(1u8);
        let order_divides =
            |g: &BigUint, divisor: &BigUint| g.mod_pow(&(&phi / divisor), &modulus) == one;
        let g = loop {
            let mut g = BigUint::from(1u8);
            for &prime in &primes {
                let small = BigUint::from(prime);
                let part = loop {
                    let part = random_prime(rng, strength, certainty);
                    if !order_divides(&part, &small) {
                        break part;
                    }
                };
                g = (g * part.mod_pow(&(&sigma / &small), &modulus)) % &n;
            }
            if primes
                .iter()
                .any(|&prime| order_divides(&g, &BigUint::from(prime)))
            {
                continue;
            }
            if order_divides(&g, &BigUint::from(4u8))
                || order_divides(&g, &p_prime)
                || order_divides(&g, &q_prime)
                || order_divides(&g, &a)
                || order_divides(&g, &b)
            {
                continue;
            }
            break g;
        };

        let sigma_bits = sigma.bits();
        let g = PaddedBigUint::from(g);
        let n = PaddedBigUint::from(n);
        Ok((
            NaccacheSternPublicKey::new(g.clone(), n.clone(), sigma_bits),
            NaccacheSternPrivateKey::new(g, n, sigma_bits, primes, PaddedBigUint::from(phi)),
        ))
    }
}

/// 強度扣掉 σ 的位元數與 48，留給 a、b 的位元數，同 BC。常數時間。
fn remaining_strength(strength: u32, sigma: &BigUint) -> i64 {
    i64::from(strength) - i64::from(sigma.bits()) - 48
}

/// BC 的 `PermuteList`：依序把每個元素插到 0 到目前長度之間的隨機位置。變動時間：只在
/// 產生金鑰時使用。
fn permute(list: &[u32], rng: &mut dyn CryptoRng) -> Vec<u32> {
    let mut permuted = Vec::with_capacity(list.len());
    for &element in list {
        let index = below(rng, permuted.len() as u32 + 1) as usize;
        permuted.insert(index, element);
    }
    permuted
}

/// `[0, bound)` 中均勻的隨機整數，以拒絕取樣避免偏差，同 BC 的 `Next(bound)`。變動時間：
/// 只在產生金鑰時使用。
fn below(rng: &mut dyn CryptoRng, bound: u32) -> u32 {
    let zone = u32::MAX - u32::MAX % bound;
    loop {
        let value = rng.next_u32();
        if value < zone {
            return value % bound;
        }
    }
}

/// BC 的 `CreateRandomPrime`：恰好 `bits` 位元的隨機質數，檢定到 `certainty`。變動時間：
/// 只在產生金鑰時使用。
fn random_prime(rng: &mut dyn CryptoRng, bits: u32, certainty: u32) -> BigUint {
    BigUint::random_probable_prime(rng, bits, rounds(certainty, bits))
}

/// 隨機挑選的 `bits` 位元候選值檢定到 `certainty` 所需的 Miller-Rabin 輪數，同 BC 的
/// `RabinMillerTest` 在 `randomlySelected` 時的算法。變動時間：只用於公開值。
fn rounds(certainty: u32, bits: u32) -> u32 {
    let rounds = (certainty - 1) / 2 + 1;
    let for_certainty_100 = match bits {
        1024.. => 4,
        512.. => 8,
        256.. => 16,
        _ => 50,
    };
    if certainty < 100 {
        rounds.min(for_certainty_100)
    } else {
        rounds - 50 + for_certainty_100
    }
}
