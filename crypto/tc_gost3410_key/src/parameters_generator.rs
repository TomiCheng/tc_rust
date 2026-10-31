use crate::math::{next_int, next_long, random_bits};
use crate::{Gost3410Error, Gost3410Parameters, Gost3410ValidationParameters};
use alloc::vec;
use rand_core::CryptoRng;
use tc_bigint::{BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};

/// BC 的 `Gost3410ParametersGenerator`：GOST R 34.10-94 附錄 A 的程序。程序 1 以 16 位元的
/// 線性同餘產生器（512 位元用程序 A、1024 位元用程序 B），程序 2 以 32 位元的（A'、B'），
/// 再以程序 C 找生成元 a。亂數的讀法照 BC，同樣的亂數得到同樣的參數。
pub struct Gost3410ParametersGenerator<'a> {
    state: Option<(u32, u32, &'a mut dyn CryptoRng)>,
}

impl<'a> Gost3410ParametersGenerator<'a> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }

    /// BC 的 `Init`：p 的位元數（512 或 1024）、程序（1 或 2）與亂數來源。不支援的值回傳
    /// 錯誤；BC 要到產生時才丟出，且把 1 以外的程序都當成 2。常數時間。
    pub fn init(
        &mut self,
        size: u32,
        procedure: u32,
        rng: &'a mut dyn CryptoRng,
    ) -> Result<(), Gost3410Error> {
        self.state = None;
        if size != 512 && size != 1024 {
            return Err(Gost3410Error::InvalidSize);
        }
        if procedure != 1 && procedure != 2 {
            return Err(Gost3410Error::InvalidProcedure);
        }
        self.state = Some((size, procedure, rng));
        Ok(())
    }

    /// BC 的 `GenerateParameters`：先讀 x0 與 c，產生 p 與 q，再以程序 C 找 a，並附上
    /// x0、c 為驗證資料。變動時間：產生的是公開值。
    pub fn generate_parameters(&mut self) -> Result<Gost3410Parameters, Gost3410Error> {
        let (size, procedure, rng) = self.state.as_mut().ok_or(Gost3410Error::NotInitialized)?;
        let (p, q, validation) = if *procedure == 1 {
            let x0 = next_int(&mut **rng);
            let c = next_int(&mut **rng);
            let (y0, increment) = short_start(&mut **rng, x0, c);
            let lcg = Lcg::short(increment);
            let (p, q) = primes(&lcg, *size, y0);
            (p, q, Gost3410ValidationParameters::new(x0, c))
        } else {
            let x0 = next_long(&mut **rng);
            let c = next_long(&mut **rng);
            let (y0, increment) = long_start(&mut **rng, x0, c);
            let lcg = Lcg::long(increment);
            let (p, q) = primes(&lcg, *size, y0);
            (p, q, Gost3410ValidationParameters::new_long(x0, c))
        };
        let a = procedure_c(&mut **rng, &p, &q);
        Ok(Gost3410Parameters::new(
            PaddedBigUint::from(p),
            PaddedBigUint::from(q),
            PaddedBigUint::from(a),
        )
        .with_validation(validation))
    }
}

impl Default for Gost3410ParametersGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// 程序的線性同餘產生器 y ← (y·a + c) mod 2^bits，以及它的最小質數。
struct Lcg {
    bits: u32,
    multiplier: u64,
    increment: u64,
    min_prime: u64,
}

impl Lcg {
    /// 程序 A、B 的 16 位元產生器。常數時間。
    fn short(increment: u64) -> Self {
        Self {
            bits: 16,
            multiplier: 19381,
            increment,
            min_prime: 0x8003,
        }
    }

    /// 程序 A'、B' 的 32 位元產生器。常數時間。
    fn long(increment: u64) -> Self {
        Self {
            bits: 32,
            multiplier: 97781173,
            increment,
            min_prime: 0x8000_000B,
        }
    }

    /// 下一個值。常數時間。
    fn next(&self, y: u64) -> u64 {
        let modulus = 1u128 << self.bits;
        ((u128::from(y) * u128::from(self.multiplier) + u128::from(self.increment)) % modulus)
            as u64
    }

    /// BC 的 step 5–8：從 y0 起算 `count` 個值，拼成 Y = Σ yⱼ·2^(bits·j)，回傳 Y 與下一個
    /// 起點 y_count。變動時間：只用於公開的參數。
    fn block(&self, y0: u64, count: u32) -> (BigUint, u64) {
        let mut y = y0;
        let mut sum = BigUint::from(0u8);
        for j in 0..count {
            sum += BigUint::from(y) << (self.bits * j);
            y = self.next(y);
        }
        (sum, y)
    }
}

/// 程序 A／B 的 x0 與 c 檢查（BC 的 16 位元版）：x0 在 `[0, 65536]`、c 在 `[2, 65536]`，
/// 否則重讀。變動時間：只用於公開的參數。
fn short_start(rng: &mut dyn CryptoRng, mut x0: i32, mut c: i32) -> (u64, u64) {
    while !(0..=65536).contains(&x0) {
        x0 = next_int(rng) / 32768;
    }
    while !(0..=65536).contains(&c) || c / 2 == 0 {
        c = next_int(rng) / 32768 + 1;
    }
    (x0 as u64, c as u64)
}

/// 程序 A'／B' 的 x0 與 c 檢查（BC 的 32 位元版）：x0 在 `[0, 2^32]`、c 在 `[2, 2^32]`，
/// 否則重讀。變動時間：只用於公開的參數。
fn long_start(rng: &mut dyn CryptoRng, mut x0: i64, mut c: i64) -> (u64, u64) {
    const LIMIT: i64 = 4_294_967_296;
    while !(0..=LIMIT).contains(&x0) {
        x0 = i64::from(next_int(rng)) * 2;
    }
    while !(0..=LIMIT).contains(&c) || c / 2 == 0 {
        c = i64::from(next_int(rng)) * 2 + 1;
    }
    (x0 as u64, c as u64)
}

/// 512 位元用程序 A（或 A'），1024 位元用程序 B（或 B'），回傳 p 與 q。變動時間：只用於
/// 公開的參數。
fn primes(lcg: &Lcg, size: u32, y0: u64) -> (BigUint, BigUint) {
    if size == 512 {
        let (_, p, q) = procedure_a(lcg, y0, 512);
        (p, q)
    } else {
        procedure_b(lcg, y0)
    }
}

/// 2^exponent mod modulus 是否為 1。變動時間：只用於公開的參數。
fn two_power_is_one(exponent: &BigUint, modulus: &BigUint) -> bool {
    let modulus = NonZero::new(modulus.clone()).expect("a candidate prime is not zero");
    BigUint::from(2u8).mod_pow(exponent, &modulus) == BigUint::from(1u8)
}

/// BC 的 `procedure_A`（與 `procedure_Aa`）：由小到大逐級產生質數 p[m] = N·p[m+1] + 1，
/// 回傳下一個起點 y0、`size` 位元的 p[0] 與 p[1]。變動時間：只用於公開的參數。
fn procedure_a(lcg: &Lcg, mut y0: u64, size: u32) -> (u64, BigUint, BigUint) {
    let mut t = vec![size];
    while *t.last().expect("t starts with size") > lcg.bits {
        let half = t.last().expect("t is not empty") / 2;
        t.push(half);
    }
    let s = t.len() - 1;
    let mut p = vec![BigUint::from(0u8); s + 1];
    p[s] = BigUint::from(lcg.min_prime);
    for m in (0..s).rev() {
        let rm = t[m] / lcg.bits;
        'step6: loop {
            let (ym, next) = lcg.block(y0, rm);
            y0 = next;
            let one = BigUint::from(1u8);
            let mut n = (one.clone() << (t[m] - 1)) / &p[m + 1]
                + (ym << (t[m] - 1)) / (p[m + 1].clone() << (lcg.bits * rm));
            if n.bit(0) {
                n += 1u32;
            }
            loop {
                let product = &n * &p[m + 1];
                if product.bits() > t[m] {
                    continue 'step6;
                }
                let candidate = &product + 1u32;
                if two_power_is_one(&product, &candidate) && !two_power_is_one(&n, &candidate) {
                    p[m] = candidate;
                    break;
                }
                n += 2u32;
            }
            break;
        }
    }
    let p1 = p.swap_remove(1);
    let p0 = p.swap_remove(0);
    (y0, p0, p1)
}

/// BC 的 `procedure_B`（與 `procedure_Bb`）：以程序 A 產生 256 位元的 q 與 512 位元的 Q，
/// 再找 1024 位元的質數 p = q·Q·N + 1，回傳 p 與 q。變動時間：只用於公開的參數。
fn procedure_b(lcg: &Lcg, y0: u64) -> (BigUint, BigUint) {
    const TP: u32 = 1024;
    let (y0, q, _) = procedure_a(lcg, y0, 256);
    let (mut y0, big_q, _) = procedure_a(lcg, y0, 512);
    let qq = &q * &big_q;
    let count = TP / lcg.bits;
    'step3: loop {
        let (y, next) = lcg.block(y0, count);
        y0 = next;
        let one = BigUint::from(1u8);
        let mut n = (one << (TP - 1)) / &qq + (y << (TP - 1)) / (qq.clone() << 1024);
        if n.bit(0) {
            n += 1u32;
        }
        loop {
            let product = &qq * &n;
            if product.bits() > TP {
                continue 'step3;
            }
            let p = &product + 1u32;
            if two_power_is_one(&product, &p) && !two_power_is_one(&(&q * &n), &p) {
                return (p, q);
            }
            n += 2u32;
        }
    }
}

/// BC 的 `procedure_C`：抽 p 的位元數的 d，1 < d < p − 1 時 a = d^((p − 1) / q) mod p，
/// 不是 1 就回傳。變動時間：產生的是公開的生成元。
fn procedure_c(rng: &mut dyn CryptoRng, p: &BigUint, q: &BigUint) -> BigUint {
    let one = BigUint::from(1u8);
    let p_minus_one = p - &one;
    let exponent = p_minus_one.clone() / q;
    let modulus = NonZero::new(p.clone()).expect("p is not zero");
    loop {
        let d = BigUint::from(random_bits(rng, p.bits()));
        if d > one && d < p_minus_one {
            let a = d.mod_pow(&exponent, &modulus);
            if a != one {
                return a;
            }
        }
    }
}
