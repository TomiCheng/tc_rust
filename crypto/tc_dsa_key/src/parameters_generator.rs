use crate::{DsaError, DsaParameterGenerationParams, DsaParameters, DsaValidationParameters};
use alloc::string::ToString;
use alloc::vec;
use core::fmt::Display;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint, RandomRange};
use tc_digest::Digest;
use tc_modular::{ModPow, NonZero};
use tc_prime::Primality;
use tc_sha::Sha1Digest;

/// BC 的 `DsaParametersGenerator`：FIPS 186-2（SHA-1，p 為 512 到 1024 位元）或 FIPS 186-3
/// （L 與 N 由 [`DsaParameterGenerationParams`] 給）產生 p、q、g 與驗證資料。雜湊預設是
/// SHA-1。
pub struct DsaParametersGenerator<'a, D = Sha1Digest> {
    digest: D,
    settings: Option<Settings<'a>>,
}

/// `init` 收下的長度、certainty、亂數來源與程序。
struct Settings<'a> {
    l: u32,
    n: u32,
    certainty: u32,
    rng: &'a mut dyn CryptoRng,
    fips186_3: bool,
    usage_index: Option<u8>,
}

impl DsaParametersGenerator<'_> {
    /// 以 SHA-1 為雜湊、尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self::with_digest(Sha1Digest::new())
    }
}

impl Default for DsaParametersGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, D> DsaParametersGenerator<'a, D> {
    /// 以 `digest` 為雜湊、尚未 `init` 的產生器。常數時間。
    pub fn with_digest(digest: D) -> Self {
        Self {
            digest,
            settings: None,
        }
    }
}

impl<'a, D: Digest + Display> DsaParametersGenerator<'a, D> {
    /// BC 的 `Init(size, certainty, random)`：FIPS 186-2，p 為 `size` 位元（512 到 1024、64 的
    /// 倍數），q 為 160 位元，雜湊要是 SHA-1。失敗時維持未初始化。變動時間：只依公開值。
    pub fn init_fips186_2(
        &mut self,
        size: u32,
        certainty: u32,
        rng: &'a mut dyn CryptoRng,
    ) -> Result<(), DsaError> {
        self.settings = None;
        if !(512..=1024).contains(&size) || size % 64 != 0 {
            return Err(DsaError::InvalidSize);
        }
        if self.digest.to_string() != "SHA-1" {
            return Err(DsaError::UnsuitableDigest);
        }
        if certainty == 0 {
            return Err(DsaError::InvalidCertainty);
        }
        self.settings = Some(Settings {
            l: size,
            n: 160,
            certainty,
            rng,
            fips186_3: false,
            usage_index: None,
        });
        Ok(())
    }

    /// BC 的 `Init(DsaParameterGenerationParameters)`：FIPS 186-3，(L, N) 要是 (1024, 160)、
    /// (2048, 224)、(2048, 256) 或 (3072, 256)，雜湊至少 N 位元。失敗時維持未初始化。變動
    /// 時間：只依公開值。
    pub fn init_fips186_3(
        &mut self,
        params: DsaParameterGenerationParams<'a>,
    ) -> Result<(), DsaError> {
        self.settings = None;
        if !matches!(
            (params.l, params.n),
            (1024, 160) | (2048, 224) | (2048, 256) | (3072, 256)
        ) {
            return Err(DsaError::InvalidLengths);
        }
        if self.digest.digest_size() * 8 < params.n as usize {
            return Err(DsaError::UnsuitableDigest);
        }
        if params.certainty == 0 {
            return Err(DsaError::InvalidCertainty);
        }
        self.settings = Some(Settings {
            l: params.l,
            n: params.n,
            certainty: params.certainty,
            rng: params.rng,
            fips186_3: true,
            usage_index: params.usage_index,
        });
        Ok(())
    }

    /// BC 的 `GenerateParameters`：依 `init` 選定的程序產生參數。`init` 之前回傳錯誤。變動
    /// 時間：參數是公開的。
    pub fn generate_parameters(&mut self) -> Result<DsaParameters, DsaError> {
        let mut settings = self.settings.take().ok_or(DsaError::NotInitialized)?;
        let params = if settings.fips186_3 {
            self.fips186_3(&mut settings)
        } else {
            self.fips186_2(&mut settings)
        };
        self.settings = Some(settings);
        Ok(params)
    }

    /// `input` 的雜湊寫進 `output`。變動時間：只用於公開的 seed。
    fn hash(&mut self, input: &[u8], output: &mut [u8]) {
        self.digest.update(input);
        self.digest.do_final(output);
    }

    /// BC 的 `GenerateParameters_FIPS186_2`。變動時間：參數是公開的。
    fn fips186_2(&mut self, settings: &mut Settings<'_>) -> DsaParameters {
        let l = settings.l as usize;
        let n = (l - 1) / 160;
        let mut seed = [0u8; 20];
        let (mut part1, mut part2) = ([0u8; 20], [0u8; 20]);
        let mut w = vec![0u8; l / 8];
        loop {
            settings.rng.fill_bytes(&mut seed);
            self.hash(&seed, &mut part1);
            let mut next = seed;
            increment(&mut next);
            self.hash(&next, &mut part2);
            let mut u = [0u8; 20];
            for ((u, a), b) in u.iter_mut().zip(&part1).zip(&part2) {
                *u = a ^ b;
            }
            u[0] |= 0x80;
            u[19] |= 0x01;
            let q = big(&u);
            if !is_prime(&q, settings) {
                continue;
            }

            let mut offset = seed;
            increment(&mut offset);
            for counter in 0..4096u32 {
                for k in 0..n {
                    increment(&mut offset);
                    self.hash(&offset, &mut part1);
                    let end = w.len() - k * 20;
                    w[end - 20..end].copy_from_slice(&part1);
                }
                increment(&mut offset);
                self.hash(&offset, &mut part1);
                let rest = w.len() - n * 20;
                w[..rest].copy_from_slice(&part1[20 - rest..]);
                w[0] |= 0x80;
                if let Some(p) = candidate_p(&big(&w), &q, settings) {
                    let g = unverifiable_generator(&p, &q, settings);
                    return parameters(
                        p,
                        q,
                        g,
                        DsaValidationParameters::new(seed.to_vec(), counter),
                    );
                }
            }
        }
    }

    /// BC 的 `GenerateParameters_FIPS186_3`。變動時間：參數是公開的。
    fn fips186_3(&mut self, settings: &mut Settings<'_>) -> DsaParameters {
        let (l, n) = (settings.l, settings.n);
        let outlen = self.digest.digest_size() * 8;
        let blocks = (l as usize - 1) / outlen;
        let tail = (l as usize - 1) % outlen;
        let mut seed = vec![0u8; n as usize / 8];
        let mut output = vec![0u8; self.digest.digest_size()];
        loop {
            settings.rng.fill_bytes(&mut seed);
            self.hash(&seed, &mut output);
            let mut q = big(&output) % &power_of_two(n - 1);
            q.set_bit(0, true);
            q.set_bit(n - 1, true);
            if !is_prime(&q, settings) {
                continue;
            }

            let mut offset = seed.clone();
            for counter in 0..4 * l {
                let mut w = BigUint::from(0u8);
                for j in 0..=blocks {
                    increment(&mut offset);
                    self.hash(&offset, &mut output);
                    let mut v = big(&output);
                    if j == blocks {
                        v %= &power_of_two(tail as u32);
                    }
                    w += v << (j * outlen) as u32;
                }
                let mut x = w;
                x.set_bit(l - 1, true);
                let Some(p) = candidate_p(&x, &q, settings) else {
                    continue;
                };
                if let Some(index) = settings.usage_index {
                    if let Some(g) = self.verifiable_generator(&p, &q, &seed, index) {
                        let validation = DsaValidationParameters::new(seed.clone(), counter)
                            .with_usage_index(index);
                        return parameters(p, q, g, validation);
                    }
                }
                let g = unverifiable_generator(&p, &q, settings);
                return parameters(p, q, g, DsaValidationParameters::new(seed.clone(), counter));
            }
        }
    }

    /// BC 的 `CalculateGenerator_FIPS186_3_Verifiable`（FIPS 186-3 A.2.3）：
    /// W = H(seed ‖ "ggen" ‖ index ‖ count)，g = W^((p − 1) / q) mod p，直到 g ≥ 2；65535 次都
    /// 不成時回傳 `None`。變動時間：參數是公開的。
    fn verifiable_generator(
        &mut self,
        p: &BigUint,
        q: &BigUint,
        seed: &[u8],
        index: u8,
    ) -> Option<BigUint> {
        let e = (p - 1u32) / q;
        let modulus = NonZero::new(p.clone())?;
        let mut u = [seed, b"ggen", &[index, 0, 0]].concat();
        let mut w = vec![0u8; self.digest.digest_size()];
        for _ in 1..(1u32 << 16) {
            increment(&mut u);
            self.hash(&u, &mut w);
            let g = big(&w).mod_pow(&e, &modulus);
            if g >= BigUint::from(2u8) {
                return Some(g);
            }
        }
        None
    }
}

/// X 調成 p = X − (X mod 2q − 1)：位元數要恰好是 L，且通過質數檢定。變動時間：參數是
/// 公開的。
fn candidate_p(x: &BigUint, q: &BigUint, settings: &mut Settings<'_>) -> Option<BigUint> {
    let c = x % &(q << 1u32);
    let p = x - &(c - 1u32);
    (p.bits() == settings.l && is_prime(&p, settings)).then_some(p)
}

/// BC 的 `CalculateGenerator_FIPS186_2`（也是 FIPS 186-3 不可驗證的作法）：h 在
/// `[2, p − 2]` 均勻挑選，g = h^((p − 1) / q) mod p，直到 g > 1。h 由 `tc_bigint` 的
/// `random_range` 抽，讀亂數的方式與 BC 不同。變動時間：參數是公開的。
fn unverifiable_generator(p: &BigUint, q: &BigUint, settings: &mut Settings<'_>) -> BigUint {
    let e = (p - 1u32) / q;
    let modulus = NonZero::new(p.clone()).expect("p is an odd prime");
    let low = PaddedBigUint::from(2u8);
    let high = PaddedBigUint::from(p - 1u32);
    loop {
        let h = BigUint::from(PaddedBigUint::random_range(&mut *settings.rng, &low, &high));
        let g = h.mod_pow(&e, &modulus);
        if g.bits() > 1 {
            return g;
        }
    }
}

/// 以 BC 的 `IsProbablePrime(certainty)` 的強度檢定。變動時間：只用於公開的候選值。
fn is_prime(candidate: &BigUint, settings: &mut Settings<'_>) -> bool {
    !candidate.has_small_factor()
        && candidate.is_probable_prime(
            rounds(settings.certainty, candidate.bits()),
            &mut *settings.rng,
        )
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

/// 組出參數。變動時間：參數是公開的。
fn parameters(
    p: BigUint,
    q: BigUint,
    g: BigUint,
    validation: DsaValidationParameters,
) -> DsaParameters {
    DsaParameters::new(p.into(), q.into(), g.into()).with_validation(validation)
}

/// 大端序的位元組讀成整數。變動時間：只用於公開值。
fn big(bytes: &[u8]) -> BigUint {
    let Ok(value) = BigUint::from_be(bytes);
    value
}

/// 2^`bits`。變動時間：只用於公開值。
fn power_of_two(bits: u32) -> BigUint {
    let mut value = BigUint::from(0u8);
    value.set_bit(bits, true);
    value
}

/// BC 的 `Inc`：把位元組當大端序整數加一，溢位時繞回。變動時間：只用於公開的 seed。
fn increment(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
