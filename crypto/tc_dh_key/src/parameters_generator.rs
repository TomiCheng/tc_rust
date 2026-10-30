use crate::math::{naf_weight, rem_u32};
use crate::small_primes::PRIME_LISTS;
use crate::{DhError, DhParameters};
use alloc::vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};
use tc_prime::Primality;

/// BC 的 `DHParametersGenerator`：產生安全質數 p = 2q + 1，g 固定為 2，j 為 2。
/// 產生很慢，2048 位元可能要數十秒到數分鐘。
pub struct DhParametersGenerator<'a> {
    state: Option<(u32, u32, &'a mut dyn CryptoRng)>,
}

impl<'a> DhParametersGenerator<'a> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }

    /// 設定 p 的位元數、質數檢定的 certainty 與亂數來源（BC 的 `Init`）。p 少於 64 位元或
    /// certainty 為 0 時回傳錯誤；BC 要到產生時才丟出。常數時間。
    pub fn init(
        &mut self,
        size: u32,
        certainty: u32,
        rng: &'a mut dyn CryptoRng,
    ) -> Result<(), DhError> {
        if size < 64 {
            return Err(DhError::InvalidSize);
        }
        if certainty == 0 {
            return Err(DhError::InvalidCertainty);
        }
        self.state = Some((size, certainty, rng));
        Ok(())
    }

    /// BC 的 `GenerateParameters`：p 為安全質數且 p ≡ 7 (mod 8)，使 2 生成 q 階子群，
    /// 回傳 p、g = 2、q 與 j = 2。變動時間：產生的是公開值。
    pub fn generate_parameters(&mut self) -> Result<DhParameters, DhError> {
        let (size, certainty, rng) = self.state.as_mut().ok_or(DhError::NotInitialized)?;
        let (p, q) = safe_primes(*size, *certainty, &mut **rng, true);
        Ok(
            DhParameters::new(PaddedBigUint::from(p), PaddedBigUint::from(2u8))
                .with_q(PaddedBigUint::from(q))
                .with_j(PaddedBigUint::from(2u8)),
        )
    }
}

impl Default for DhParametersGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// BC `DHParametersHelper.GenerateSafePrimes`（Handbook of Applied Cryptography 4.86）：
/// `bits` 位元的質數對 p、q，p = 2q + 1。`for_generator2` 時 p ≡ 23 (mod 24)，2 是模 p 的
/// 二次剩餘；否則 p ≡ 11 (mod 12)。
///
/// 從隨機起點以步長 12 或 24 前進至多 256 次：先排除 p 或 q 有小質因數者，再以 Fermat
/// 檢定 p（q 是質數時依 Pocklington 判準即足以證明 p 是質數），以 Miller-Rabin 檢定 q，
/// 最後要求 p 的 NAF 權重至少是位元數的四分之一，以抵禦針對低權重質數的數域篩法。
/// 變動時間：產生的是公開值。
pub(crate) fn safe_primes(
    bits: u32,
    certainty: u32,
    rng: &mut dyn CryptoRng,
    for_generator2: bool,
) -> (BigUint, BigUint) {
    let (low_bits_set, inc3, step) = if for_generator2 {
        (0x07u8, -8i32, 24u32)
    } else {
        (0x03u8, 4i32, 12u32)
    };
    let min_weight = bits >> 2;
    let byte_length = bits.div_ceil(8) as usize;
    let extra_bits = byte_length as u32 * 8 - bits;
    let two = BigUint::from(2u8);
    let mut bytes = vec![0u8; byte_length];
    loop {
        rng.fill_bytes(&mut bytes);
        // 去掉多出的位元，設定最高位與最低幾位。
        bytes[0] = (bytes[0] & (0xffu8 >> extra_bits)) | (0x80u8 >> extra_bits);
        bytes[byte_length - 1] |= low_bits_set;
        let mut p = BigUint::from_be(&bytes).expect("bytes always decode");

        // 調整到 p ≡ 2 (mod 3)，結果是 p ≡ 11 (mod 12)，或 for_generator2 時 p ≡ 23 (mod 24)。
        let p_mod3 = rem_u32(&p, 3);
        if p_mod3 != 2 {
            let delta = (2 - p_mod3 as i32) * inc3;
            p = if delta >= 0 {
                p + delta as u32
            } else {
                p - delta.unsigned_abs()
            };
        }

        let mut count = 0;
        loop {
            count += 1;
            if count > 256 || p.bits() != bits {
                break;
            }
            if !has_any_small_factors_safe(&p) {
                let modulus = NonZero::new(p.clone()).expect("p is odd");
                if two.mod_pow(&p, &modulus) == two {
                    let q = &p >> 1;
                    if q.is_probable_prime(rounds(certainty, q.bits()), rng)
                        && naf_weight(p.as_limbs()) >= min_weight
                    {
                        return (p, q);
                    }
                }
                // 從新的隨機起點重來。
                break;
            }
            p += step;
        }
    }
}

/// BC `DHParametersHelper.HasAnySmallFactorsSafe`：餘數為 0 表示 p 有該小質因數，為 1
/// 表示 p − 1 有，也就是 q 有。變動時間：只用於公開值。
fn has_any_small_factors_safe(x: &BigUint) -> bool {
    PRIME_LISTS.iter().any(|primes| {
        let product = primes.iter().product::<u32>();
        let r = rem_u32(x, product);
        primes.iter().any(|&prime| r % prime < 2)
    })
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
