use tc_bigint::BigInt;

use super::PRECISION;

/// BC 的 `ZTauElement`：Z[τ] 的元素 u + vτ。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ZTauElement {
    pub(super) u: BigInt,
    pub(super) v: BigInt,
}

/// 一條 Koblitz 曲線的 partial modular reduction 常數，BC `PartModPreCompInfo` 加上 a、μ、m。
#[derive(Clone, Debug)]
pub(super) struct Reduction {
    pub(super) a: u8,
    pub(super) mu: i8,
    m: u32,
    vm: BigInt,
    s0: BigInt,
    s1: BigInt,
}

impl Reduction {
    /// BC `PartModPreCompCallback` 的 Koblitz 分支：V_m = 2^m + 1 - n·h，以及 `GetSi`。
    pub(super) fn new(m: u32, a: u8, order: &BigInt, cofactor: &BigInt) -> Self {
        let mu = mu(a);
        let vm = (BigInt::from(1u8) << m) + BigInt::from(1u8) - &(order * cofactor);
        let (s0, s1) = si(m, a, mu, cofactor);
        Self {
            a,
            mu,
            m,
            vm,
            s0,
            s1,
        }
    }

    /// BC `PartModReduction`：ρ = k partmod δ，δ = (τ^m - 1) / (τ - 1)。
    pub(super) fn part_mod(&self, k: &BigInt) -> ZTauElement {
        let d0 = if self.mu == 1 {
            &self.s0 + &self.s1
        } else {
            &self.s0 - &self.s1
        };
        let lambda0 = approximate_division(k, &self.s0, &self.vm, self.a, self.m, PRECISION);
        let lambda1 = approximate_division(k, &self.s1, &self.vm, self.a, self.m, PRECISION);
        let q = round(&lambda0, &lambda1, self.mu);
        let r0 = k - &(&d0 * &q.u) - &((&self.s1 * &q.v) << 1);
        let r1 = &self.s1 * &q.u - &(&self.s0 * &q.v);
        ZTauElement { u: r0, v: r1 }
    }
}

/// BC `GetMu`：a = 0 時 μ = -1，a = 1 時 μ = 1。
pub(super) fn mu(a: u8) -> i8 {
    if a == 0 { -1 } else { 1 }
}

/// BC 的 `SimpleBigDecimal`：value / 2^scale。
#[derive(Clone, Debug)]
struct SimpleBigDecimal {
    value: BigInt,
    scale: u32,
}

impl SimpleBigDecimal {
    fn add(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.scale, rhs.scale);
        Self {
            value: &self.value + &rhs.value,
            scale: self.scale,
        }
    }

    fn subtract(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.scale, rhs.scale);
        Self {
            value: &self.value - &rhs.value,
            scale: self.scale,
        }
    }

    fn subtract_integer(&self, rhs: &BigInt) -> Self {
        Self {
            value: &self.value - &(rhs << self.scale),
            scale: self.scale,
        }
    }

    fn compare_integer(&self, rhs: i8) -> core::cmp::Ordering {
        self.value.cmp(&(BigInt::from(rhs) << self.scale))
    }

    // BC `Round`：加上 1/2 後取 floor。
    fn round(&self) -> BigInt {
        (&self.value + &(BigInt::from(1u8) << (self.scale - 1))) >> self.scale
    }
}

/// BC `ApproximateDivisionByN`：k·s / n 取 c 位小數的近似。
fn approximate_division(
    k: &BigInt,
    s: &BigInt,
    vm: &BigInt,
    a: u8,
    m: u32,
    c: u32,
) -> SimpleBigDecimal {
    let big_k = (m + 5) / 2 + c;
    let ns = k >> (m + u32::from(a) - big_k - 2);
    let gs = s * &ns;
    let hs = &gs >> m;
    let js = vm * &hs;
    let gs_plus_js = &gs + &js;
    let mut ls = &gs_plus_js >> (big_k - c);
    if gs_plus_js.bit(big_k - c - 1) {
        ls += 1u32;
    }
    SimpleBigDecimal {
        value: ls,
        scale: c,
    }
}

/// BC `Round`：把 λ0 + λ1·τ 捨入到 Z[τ] 中最近的元素。
fn round(lambda0: &SimpleBigDecimal, lambda1: &SimpleBigDecimal, mu: i8) -> ZTauElement {
    let f0 = lambda0.round();
    let f1 = lambda1.round();
    let eta0 = lambda0.subtract_integer(&f0);
    let eta1 = lambda1.subtract_integer(&f1);

    let twice_eta0 = eta0.add(&eta0);
    let eta = if mu == 1 {
        twice_eta0.add(&eta1)
    } else {
        twice_eta0.subtract(&eta1)
    };
    let three_eta1 = eta1.add(&eta1).add(&eta1);
    let four_eta1 = three_eta1.add(&eta1);
    let (check1, check2) = if mu == 1 {
        (eta0.subtract(&three_eta1), eta0.add(&four_eta1))
    } else {
        (eta0.add(&three_eta1), eta0.subtract(&four_eta1))
    };

    let mut h0 = 0i8;
    let mut h1 = 0i8;
    if eta.compare_integer(1).is_ge() {
        if check1.compare_integer(-1).is_lt() {
            h1 = mu;
        } else {
            h0 = 1;
        }
    } else if check2.compare_integer(2).is_ge() {
        h1 = mu;
    }
    if eta.compare_integer(-1).is_lt() {
        if check1.compare_integer(1).is_ge() {
            h1 = -mu;
        } else {
            h0 = -1;
        }
    } else if check2.compare_integer(-2).is_lt() {
        h1 = -mu;
    }
    ZTauElement {
        u: f0 + BigInt::from(h0),
        v: f1 + BigInt::from(h1),
    }
}

/// BC `GetSi`：s0 與 s1，由 Lucas 序列 U_(m+3-a) 與餘因子 2 或 4 得到。
fn si(m: u32, a: u8, mu: i8, cofactor: &BigInt) -> (BigInt, BigInt) {
    let shifts = if *cofactor == BigInt::from(2u8) {
        1
    } else {
        assert!(
            *cofactor == BigInt::from(4u8),
            "a Koblitz cofactor is 2 or 4"
        );
        2
    };
    let (mut u0, mut u1) = lucas(mu, m + 3 - u32::from(a));
    if mu == 1 {
        u0 = -u0;
        u1 = -u1;
    }
    let s0 = (BigInt::from(1u8) + u1) >> shifts;
    let s1 = -((BigInt::from(1u8) + u0) >> shifts);
    (s0, s1)
}

/// BC `GetLucas` 的 U 序列（`doV` 為 false）：U_0 = 0、U_1 = 1、U_(i+1) = μU_i - 2U_(i-1)，
/// 回傳 (U_(k-1), U_k)。
fn lucas(mu: i8, k: u32) -> (BigInt, BigInt) {
    let mut u0 = BigInt::from(0u8);
    let mut u1 = BigInt::from(1u8);
    for _ in 1..k {
        let s = if mu == 1 { u1.clone() } else { -&u1 };
        let u2 = s - &(&u0 << 1);
        u0 = u1;
        u1 = u2;
    }
    (u0, u1)
}

#[cfg(test)]
mod tests {
    use super::{Reduction, ZTauElement, lucas};
    use tc_bigint::BigInt;

    fn int(value: i64) -> BigInt {
        BigInt::from(value)
    }

    // U for μ = 1: 0, 1, 1, -1, -3, -1, 5, 7, -3; for μ = -1: 0, 1, -1, -1, 3, -1, -5, 7, 3.
    #[test]
    fn the_lucas_sequences_follow_their_recurrence() {
        let plus = [0, 1, 1, -1, -3, -1, 5, 7, -3];
        let minus = [0, 1, -1, -1, 3, -1, -5, 7, 3];
        for k in 1..plus.len() {
            assert_eq!(
                lucas(1, k as u32),
                (int(plus[k - 1]), int(plus[k])),
                "k = {k}"
            );
            assert_eq!(
                lucas(-1, k as u32),
                (int(minus[k - 1]), int(minus[k])),
                "k = {k}"
            );
        }
    }

    // For a scalar of up to m bits, k partmod δ has a norm of a few times n, as Solinas
    // bounds it, whatever its size before.
    #[test]
    fn a_reduced_element_has_a_small_norm_on_k_163() {
        let order = BigInt::from(1u8) << 162;
        let order = order + &hex("20108a2e0cc0d99f8a5ef");
        let reduction = Reduction::new(163, 1, &order, &int(2));
        let top = (BigInt::from(1u8) << 163) - int(1);
        for k in [
            int(1),
            int(12345),
            order.clone() - int(1),
            order.clone() + int(7),
            top,
        ] {
            let ZTauElement { u, v } = reduction.part_mod(&k);
            // N(u + vτ) = u² + μuv + 2v².
            let norm = &u * &u + &(&u * &v) + &((&v * &v) << 1);
            assert!(norm < (&order << 3), "k = {k:?}");
        }
    }

    fn hex(text: &str) -> BigInt {
        text.chars().fold(int(0), |acc, digit| {
            (acc << 4) + int(i64::from(digit.to_digit(16).unwrap()))
        })
    }
}
