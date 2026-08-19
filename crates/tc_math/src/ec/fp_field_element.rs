//! Prime-field elements for elliptic curves.
//!
//! Corresponds to `FpFieldElement` in Bouncy Castle C#
//! (`Org.BouncyCastle.Math.EC.FpFieldElement`). Binary-field (F2m) elements and
//! the common field-element abstraction will live in sibling modules later.

use core::ops::{Add, Div, Mul, Neg, Sub};

use crate::big_integer::BigInteger;

/// An element of the prime field GF(p).
///
/// Holds the field modulus `q` (the prime p) alongside the value `x`, with the
/// invariant `0 <= x < q`. Arithmetic is performed modulo `q`.
///
/// Mirrors `FpFieldElement` from Bouncy Castle. Each element carries its own
/// copy of `q` and the reduction residue `r`; both originate from the curve
/// (`FpCurve`), which computes `r` once via [`FpFieldElement::calculate_residue`]
/// and threads it into every element it creates.
#[derive(Clone)]
pub struct FpFieldElement {
    // 體域質數（模數）。
    q: BigInteger,
    // 元素值，不變式：0 <= x < q。
    x: BigInteger,
    // 快速模約簡用的預算殘值，由曲線建構時算好傳入；None 表示沒有快速形式，
    // 退回通用取模。目前僅存放，實際使用在 mod_reduce 快速路徑實作後。
    r: Option<BigInteger>,
}

impl FpFieldElement {
    /// Low-level constructor mirroring Bouncy Castle's internal
    /// `FpFieldElement(q, r, x)`: stores the value directly without reducing or
    /// range-checking it.
    ///
    /// The caller (the curve's `from_big_integer`) is responsible for ensuring
    /// `0 <= x < q` and for supplying `r` from [`calculate_residue`]. This is
    /// crate-internal (bc marks it `internal`); external callers construct field
    /// elements through the curve.
    ///
    /// [`calculate_residue`]: FpFieldElement::calculate_residue
    pub(crate) fn new(q: BigInteger, x: BigInteger, r: Option<BigInteger>) -> Self {
        FpFieldElement { q, x, r }
    }

    /// Creates a new element in the same field (sharing `q` and `r`) holding the
    /// value `x`, which the caller must already have reduced into `[0, q)`.
    ///
    /// Corresponds to the `new FpFieldElement(q, r, result)` pattern used
    /// throughout Bouncy Castle's arithmetic methods.
    fn with_value(&self, x: BigInteger) -> Self {
        FpFieldElement {
            q: self.q.clone(),
            x,
            r: self.r.clone(),
        }
    }

    /// Reduces `x` modulo `q`, using the precomputed residue `r` for a fast path
    /// when available. Mirrors Bouncy Castle's `ModReduce`.
    ///
    /// `x` may be negative or much larger than `q`; the result lands in
    /// `[0, q)`. Used by multiplication and squaring.
    fn mod_reduce(&self, x: BigInteger) -> BigInteger {
        let q = &self.q;

        // r == None：沒有快速形式，退回通用取模（非負餘數）。
        let r = match &self.r {
            None => return x.rem_euclid(q),
            Some(r) => r,
        };

        let one = BigInteger::from_u32(1); // 這條路徑會用到好幾次，綁一次重用
        let negative = x.sign() < 0;
        let mut x = if negative { x.abs() } else { x }; // 先取絕對值，最後再補回符號
        let q_len = q.bit_length();

        if r.sign() > 0 {
            // pseudo-Mersenne：反覆把 ≥ 2^qLen 的高位「折」下來。
            let q_mod = &one << q_len; // 2^qLen
            let r_is_one = r == &one;
            while x.bit_length() > q_len + 1 {
                let u = &x >> q_len; // 高位部分
                let v = &x % &q_mod; // 低 qLen 位
                let u = if r_is_one { u } else { &u * r };
                x = &u + &v;
            }
        } else {
            // Barrett：mu = −r 為預算倒數，估商 quot 後扣掉 quot·q。
            let d = ((q_len - 1) & 31) + 1;
            let mu = -r;
            let u = &mu * &(&x >> (q_len - d));
            let quot = &u >> (q_len + d);
            let v = &quot * q;
            let bk1 = &one << (q_len + d); // 2^(qLen+d)
            let v = &v % &bk1;
            x = &x % &bk1;
            x = &x - &v;
            if x.sign() < 0 {
                x = &x + &bk1;
            }
        }

        // 收尾：把 x 拉進 [0, q)。
        while &x >= q {
            x = &x - q;
        }
        // 原值為負且結果非零 → 取相反元素 q − x。
        if negative && !x.is_zero() {
            x = q - &x;
        }
        x
    }

    /// Returns `2x mod q` for a value `x` already in `[0, q)`.
    ///
    /// Corresponds to `ModDouble` in Bouncy Castle. Used by the `q ≡ 1 (mod 8)`
    /// square-root branch (`fourX = mod_double(mod_double(x))`).
    fn mod_double(&self, x: &BigInteger) -> BigInteger {
        let two_x = x << 1; // 2x
        if two_x >= self.q {
            &two_x - &self.q
        } else {
            two_x
        }
    }

    /// Returns `x/2` when `x` is even, or `(q - x)/2` when `x` is odd.
    ///
    /// Corresponds to `ModHalfAbs` in Bouncy Castle. Used by the `q ≡ 1 (mod 8)`
    /// square-root branch. `q` is an odd prime, so `q - x` is even when `x` is
    /// odd and the shift is exact.
    fn mod_half_abs(&self, x: &BigInteger) -> BigInteger {
        if x.test_bit(0) {
            let t = &self.q - x; // q − x（偶）
            &t >> 1
        } else {
            x >> 1
        }
    }

    /// Computes the Lucas-sequence pair `(U_k, V_k)` mod `q` for parameters `p`
    /// and `lucas_q`. Ported from Bouncy Castle's `LucasSequence`; used by the
    /// `q ≡ 1 (mod 8)` square-root branch.
    ///
    /// `lucas_q` is the Lucas sequence's second parameter (bc's `Q`) — not the
    /// field modulus `self.q`. Subtractions are reduced with [`Self::mod_reduce`]
    /// because the intermediate values may be negative or close to `q^2`.
    fn lucas_sequence(
        &self,
        p: &BigInteger,
        lucas_q: &BigInteger,
        k: &BigInteger,
    ) -> (BigInteger, BigInteger) {
        let n = k.bit_length();
        let s = k.get_lowest_set_bit().expect("lucas_sequence: k must be non-zero");

        let one = BigInteger::from_u32(1);

        let mut uh = one.clone(); // Uh = 1
        let mut vl = BigInteger::from_u32(2); // Vl = 2
        let mut vh = p.clone(); // Vh = P
        let mut ql = one.clone(); // Ql = 1
        let mut qh = one.clone(); // Qh = 1

        // 主迴圈：j 由高位 n-1 掃到 s+1。
        let mut j = n - 1;
        while j >= s + 1 {
            ql = self.mod_reduce(&ql * &qh);
            if k.test_bit(j) {
                qh = self.mod_reduce(&ql * lucas_q);
                uh = self.mod_reduce(&uh * &vh);
                vl = self.mod_reduce(&(&vh * &vl) - &(p * &ql));
                vh = self.mod_reduce(&(&vh * &vh) - &(&qh << 1));
            } else {
                qh = ql.clone();
                uh = self.mod_reduce(&(&uh * &vl) - &ql);
                vh = self.mod_reduce(&(&vh * &vl) - &(p * &ql));
                vl = self.mod_reduce(&(&vl * &vl) - &(&ql << 1));
            }
            j -= 1;
        }

        // 銜接區塊（bc 迴圈後那段）。
        ql = self.mod_reduce(&ql * &qh);
        qh = self.mod_reduce(&ql * lucas_q);
        uh = self.mod_reduce(&(&uh * &vl) - &ql);
        vl = self.mod_reduce(&(&vh * &vl) - &(p * &ql));
        ql = self.mod_reduce(&ql * &qh);

        // 收尾：k 的 s 個低位 0（j = 1..=s）。
        for _ in 0..s {
            uh = self.mod_reduce(&uh * &vl);
            vl = self.mod_reduce(&(&vl * &vl) - &(&ql << 1));
            ql = self.mod_reduce(&ql * &ql);
        }

        (uh, vl) // (U_k, V_k)
    }

    /// Computes the reduction residue `r` used to speed up reduction modulo `q`,
    /// matching Bouncy Castle's `FpFieldElement.CalculateResidue`.
    ///
    /// - Pseudo-Mersenne primes (top 64 bits all ones): `r = 2^k - q`, small.
    /// - Byte-aligned primes: `r = -floor(2^(2k) / q)`, a Barrett reciprocal.
    /// - Otherwise `None` — callers fall back to a generic remainder.
    ///
    /// Called once by the curve at construction; `r` only affects the speed of
    /// reduction, never the result.
    pub(crate) fn calculate_residue(q: &BigInteger) -> Option<BigInteger> {
        let bit_length = q.bit_length();
        if bit_length >= 96 {
            let one = BigInteger::from_u32(1);
            // 取 q 頂端 64 個位元。
            let first_word = q >> (bit_length - 64);
            let u64_max = &(&one << 64) - &one;
            if first_word == u64_max {
                // pseudo-Mersenne：q 頂端 64 位元全為 1，r = 2^k − q（小）。
                return Some(&(&one << bit_length) - q);
            }
            if bit_length & 7 == 0 {
                // byte 對齊長度：r = −⌊2^(2k) / q⌋（Barrett 倒數，負值）。
                return Some(-&(&(&one << (bit_length << 1)) / q));
            }
        }
        None
    }

    /// Returns the field modulus `q` (the prime p).
    pub fn q(&self) -> &BigInteger {
        &self.q
    }

    /// Returns the field size in bits, i.e. the bit length of `q`.
    ///
    /// Corresponds to `FieldSize` in Bouncy Castle.
    pub fn field_size(&self) -> u32 {
        self.q.bit_length()
    }

    /// Returns `true` if this element is the additive identity (zero).
    pub fn is_zero(&self) -> bool {
        self.x.is_zero()
    }

    /// Returns `true` if this element is the multiplicative identity (one).
    ///
    /// Mirrors Bouncy Castle's `IsOne => BitLength == 1`: only the value 1 has a
    /// bit length of exactly 1 (given the invariant `x >= 0`), so no comparison
    /// value needs to be allocated.
    pub fn is_one(&self) -> bool {
        self.x.bit_length() == 1
    }

    /// Returns `self^2` in the field, i.e. `(x^2) mod q`.
    ///
    /// Corresponds to `Square` in Bouncy Castle. Uses [`BigInteger::square`],
    /// which exploits symmetry, rather than a general multiply.
    pub fn square(&self) -> Self {
        self.with_value(self.mod_reduce(self.x.square()))
    }

    /// Returns the multiplicative inverse `x^{-1} mod q`.
    ///
    /// Corresponds to `Invert` in Bouncy Castle.
    ///
    /// # Panics
    ///
    /// Panics if this element is zero (no inverse exists), mirroring bc's
    /// `ArithmeticException`.
    //
    // TODO(ec-ct)：bc 的 Invert 走 constant-time safegcd（BigIntegers.ModOddInverse
    // → Mod.ModOddInverse，Bernstein–Yang）以防側通道。這裡先用通用的
    // BigInteger::mod_inverse（extended Euclid，變動時間）—— 正確但會洩漏時序。
    // 之後為「安全性」移植 safegcd（需要 Nat 定長 limb 層）。
    pub fn invert(&self) -> Self {
        let inv = self
            .x
            .mod_inverse(&self.q)
            .expect("FpFieldElement::invert: element is not invertible (zero)");
        self.with_value(inv)
    }

    /// Returns a square root of this element, or `None` if it is a quadratic
    /// non-residue (no square root exists in the field).
    ///
    /// The returned `z` satisfies `z^2 == self`; the other root is `-z`.
    /// Corresponds to `Sqrt` in Bouncy Castle.
    ///
    /// # Panics
    ///
    /// Panics if `q` is even (unsupported), mirroring bc's
    /// `NotImplementedException`.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() || self.is_one() {
            return Some(self.clone());
        }

        let q = &self.q;
        assert!(q.test_bit(0), "sqrt: even value of q is unsupported");

        let one = BigInteger::from_u32(1);

        if q.test_bit(1) {
            // q ≡ 3 (mod 4)：z = x^((q+1)/4)。
            let e = &(q >> 2) + &one;
            return self.check_sqrt(self.with_value(self.x.mod_pow(&e, q)));
        }

        if q.test_bit(2) {
            // q ≡ 5 (mod 8)：Atkin。
            let t1 = self.x.mod_pow(&(q >> 3), q); // x^((q-5)/8)
            let t2 = self.mod_reduce(&t1 * &self.x); // x^((q+3)/8)
            let t3 = self.mod_reduce(&t2 * &t1); // x^((q-1)/4)
            if t3 == one {
                return self.check_sqrt(self.with_value(t2));
            }
            let t4 = BigInteger::from_u32(2).mod_pow(&(q >> 2), q); // 2^((q-1)/4)
            let y = self.mod_reduce(&t2 * &t4);
            return self.check_sqrt(self.with_value(y));
        }

        // q ≡ 1 (mod 8)：Tonelli–Shanks（Lucas 序列）。
        let legendre_exponent = q >> 1; // (q-1)/2
        if self.x.mod_pow(&legendre_exponent, q) != one {
            return None; // x 非二次剩餘 → 無平方根
        }

        let four_x = self.mod_double(&self.mod_double(&self.x)); // 4X
        let k = &legendre_exponent + &one; // (q+1)/2
        let q_minus_one = q - &one;

        // 確定性探測 P = 1, 2, 3, …（取代 bc 的隨機 Arbitrary；P 只是探針，非安全敏感）。
        let mut p = one.clone();
        loop {
            if &p >= q {
                return None; // 理論上不會走到（剩餘必在 q 前命中）
            }
            // 需要 (P² − 4X) 為非剩餘：其 Legendre 次方 == q − 1。
            let legendre = self
                .mod_reduce(&(&p * &p) - &four_x)
                .mod_pow(&legendre_exponent, q);
            if legendre == q_minus_one {
                let (u, v) = self.lucas_sequence(&p, &self.x, &k);
                if self.mod_reduce(&v * &v) == four_x {
                    // V/2 即為平方根（已由 V²==4X 驗證，不需再 check_sqrt）。
                    return Some(self.with_value(self.mod_half_abs(&v)));
                }
                // U 退化才換 P 重試；否則放棄。
                if u != one && u != q_minus_one {
                    return None;
                }
            }
            p = &p + &one;
        }
    }

    /// Verifies a candidate root: `Some(z)` if `z^2 == self`, else `None`.
    /// Corresponds to bc `CheckSqrt`.
    fn check_sqrt(&self, z: Self) -> Option<Self> {
        if z.square().as_ref() == self.as_ref() {
            Some(z)
        } else {
            None
        }
    }

    /// Returns `self + 1` in the field.
    ///
    /// Corresponds to `AddOne` in Bouncy Castle. Fast path: since `x < q`, the
    /// sum is at most `q`, so the only reduction needed is mapping `q` back to
    /// `0` — no general modular reduction.
    pub fn add_one(&self) -> Self {
        let x2 = &self.x + &BigInteger::from_u32(1);
        // x < q ⇒ x+1 ≤ q；唯一環繞是 x+1 == q → 0。
        let x2 = if x2 == self.q {
            BigInteger::from_u32(0)
        } else {
            x2
        };
        self.with_value(x2)
    }

    // TODO(ec-fp)：以下運算待實作（對應 bc FpFieldElement），全部 mod q：
    //   add / subtract / multiply / divide(= self × b⁻¹) / negate(q − x) /
    //   square / invert(mod_inverse) / sqrt(Tonelli–Shanks，依 q mod 4/8 分支)。
    //   乘法/平方的約簡走 mod_reduce（屆時才使用上面的 r 做 pseudo-Mersenne /
    //   Barrett 快速路徑，None 時退回通用取模）。
    // 約定：均為 &self、回傳新元素；兩運算元須同 q（debug_assert）。
}

/// Borrows the element's value as an integer in `[0, q)`.
///
/// The trait form of Bouncy Castle's `ToBigInteger()`; clone at the call site if
/// an owned copy is needed.
impl AsRef<BigInteger> for FpFieldElement {
    fn as_ref(&self) -> &BigInteger {
        &self.x
    }
}

/// Field addition: `(x + b.x) mod q`.
///
/// Corresponds to `Add` in Bouncy Castle (`ModAdd`). Both operands must belong
/// to the same field.
impl Add for &FpFieldElement {
    type Output = FpFieldElement;

    fn add(self, rhs: &FpFieldElement) -> FpFieldElement {
        debug_assert!(self.q == rhs.q, "add: field elements from different fields");
        // 不變式 0 ≤ x, rhs.x < q ⇒ 和 < 2q，最多減一次 q 即回到 [0, q)，
        // 不必整除取模（bc ModAdd 的做法）。
        let mut sum = &self.x + &rhs.x;
        if sum >= self.q {
            sum = &sum - &self.q;
        }
        self.with_value(sum)
    }
}

/// Field subtraction: `(x - b.x) mod q`.
///
/// Corresponds to `Subtract` in Bouncy Castle (`ModSubtract`). Both operands
/// must belong to the same field.
impl Sub for &FpFieldElement {
    type Output = FpFieldElement;

    fn sub(self, rhs: &FpFieldElement) -> FpFieldElement {
        debug_assert!(self.q == rhs.q, "sub: field elements from different fields");
        // 不變式 0 ≤ x, rhs.x < q ⇒ 差 ∈ (−q, q)；為負時加一次 q 回到 [0, q)。
        let mut diff = &self.x - &rhs.x;
        if diff.sign() < 0 {
            diff = &diff + &self.q;
        }
        self.with_value(diff)
    }
}

/// Field multiplication: `(x * b.x) mod q`.
///
/// Corresponds to `Multiply` in Bouncy Castle (`ModMult` = `ModReduce(x1*x2)`).
/// Both operands must belong to the same field.
impl Mul for &FpFieldElement {
    type Output = FpFieldElement;

    fn mul(self, rhs: &FpFieldElement) -> FpFieldElement {
        debug_assert!(self.q == rhs.q, "mul: field elements from different fields");
        self.with_value(self.mod_reduce(&self.x * &rhs.x))
    }
}

/// Field division: `self * b^{-1}` in the field.
///
/// Corresponds to `Divide` in Bouncy Castle (`ModMult(x, ModInverse(b))`).
///
/// # Panics
///
/// Panics if the divisor is zero (see [`FpFieldElement::invert`]).
impl Div for &FpFieldElement {
    type Output = FpFieldElement;

    fn div(self, rhs: &FpFieldElement) -> FpFieldElement {
        debug_assert!(self.q == rhs.q, "div: field elements from different fields");
        self * &rhs.invert()
    }
}

/// Field negation: the additive inverse `(-x) mod q`, i.e. `q - x` (and `0` for
/// zero).
///
/// Corresponds to `Negate` in Bouncy Castle.
impl Neg for &FpFieldElement {
    type Output = FpFieldElement;

    fn neg(self) -> FpFieldElement {
        if self.x.is_zero() {
            // −0 = 0；bc 直接回傳自身，這裡回傳等值副本。
            self.clone()
        } else {
            // 0 < x < q ⇒ q − x ∈ (0, q)。
            self.with_value(&self.q - &self.x)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 測試輔助：模擬未來曲線建 element（算好 r 再傳入）。
    fn field_element(q: BigInteger, x: BigInteger) -> FpFieldElement {
        let r = FpFieldElement::calculate_residue(&q);
        FpFieldElement::new(q, x, r)
    }

    #[test]
    fn accessors_report_field() {
        let fe = field_element(BigInteger::from_u32(23), BigInteger::from_u32(1));
        assert_eq!(fe.field_size(), 5); // 23 = 0b10111，5 位元
        assert!(fe.is_one());
        assert!(!fe.is_zero());
    }

    #[test]
    fn residue_secp256k1_pseudo_mersenne() {
        // secp256k1 質數 p = 2^256 − 2^32 − 977，頂端 64 位元全為 1。
        let p = BigInteger::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap();
        // r = 2^256 − p = 2^32 + 977 = 4294968273。
        let r = FpFieldElement::calculate_residue(&p);
        assert_eq!(r, Some(BigInteger::from_u64(4_294_968_273)));
    }

    #[test]
    fn add_wraps_modulo_q() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(5));
        let b = field_element(q.clone(), BigInteger::from_u32(4));
        // 5 + 4 = 9 ≡ 2 (mod 7)。
        assert_eq!((&a + &b).as_ref(), &BigInteger::from_u32(2));
        // 加 0 為單位元。
        let zero = field_element(q, BigInteger::from_u32(0));
        assert_eq!((&a + &zero).as_ref(), &BigInteger::from_u32(5));
    }

    #[test]
    fn sub_borrows_modulo_q() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(3));
        let b = field_element(q.clone(), BigInteger::from_u32(5));
        // 3 − 5 = −2 ≡ 5 (mod 7)。
        assert_eq!((&a - &b).as_ref(), &BigInteger::from_u32(5));
        // 無借位情形：5 − 3 = 2。
        assert_eq!((&b - &a).as_ref(), &BigInteger::from_u32(2));
    }

    #[test]
    fn neg_is_additive_inverse() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(3));
        // −3 ≡ 4 (mod 7)。
        assert_eq!((-&a).as_ref(), &BigInteger::from_u32(4));
        // a + (−a) = 0。
        assert!((&a + &(-&a)).is_zero());
        // −0 = 0。
        let zero = field_element(q, BigInteger::from_u32(0));
        assert!((-&zero).is_zero());
    }

    #[test]
    fn mul_reduces_modulo_q() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(5));
        let b = field_element(q, BigInteger::from_u32(4));
        // 5 · 4 = 20 ≡ 6 (mod 7)。
        assert_eq!((&a * &b).as_ref(), &BigInteger::from_u32(6));
    }

    #[test]
    fn mul_matches_generic_on_large_field() {
        // secp256k1 上比對 x·y mod q 與通用取模。
        let q = secp256k1_prime();
        let xv = &q - &BigInteger::from_u32(3);
        let yv = &q - &BigInteger::from_u32(100);
        let x = field_element(q.clone(), xv.clone());
        let y = field_element(q.clone(), yv.clone());
        assert_eq!((&x * &y).as_ref(), &(&xv * &yv).rem_euclid(&q));
    }

    #[test]
    fn square_matches_self_multiply() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(5));
        // 5² = 25 ≡ 4 (mod 7)。
        assert_eq!(a.square().as_ref(), &BigInteger::from_u32(4));

        // 大體域：square 應等於 self·self。
        let q = secp256k1_prime();
        let xv = &q - &BigInteger::from_u32(7);
        let x = field_element(q, xv);
        assert_eq!(x.square().as_ref(), (&x * &x).as_ref());
    }

    #[test]
    fn div_is_multiply_by_inverse() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(6));
        let b = field_element(q.clone(), BigInteger::from_u32(3));
        // 6 / 3 = 6 · 3⁻¹ = 6 · 5 = 30 ≡ 2 (mod 7)。
        assert_eq!((&a / &b).as_ref(), &BigInteger::from_u32(2));
        // (a / b) · b = a。
        assert_eq!((&(&a / &b) * &b).as_ref(), a.as_ref());
    }

    #[test]
    fn sqrt_zero_and_one() {
        let q = BigInteger::from_u32(17);
        assert!(field_element(q.clone(), BigInteger::from_u32(0)).sqrt().unwrap().is_zero());
        assert!(field_element(q, BigInteger::from_u32(1)).sqrt().unwrap().is_one());
    }

    #[test]
    fn sqrt_q_3_mod_4() {
        // secp256k1 p ≡ 3 (mod 4)。完全平方開根，平方回原值。
        let q = secp256k1_prime();
        let a = field_element(q.clone(), &q - &BigInteger::from_u32(9));
        let sq = a.square();
        let root = sq.sqrt().expect("完全平方必為二次剩餘");
        assert_eq!(root.square().as_ref(), sq.as_ref());
    }

    #[test]
    fn sqrt_q_5_mod_8() {
        // GF(13)，13 ≡ 5 (mod 8)。QR = {1,3,4,9,10,12}。
        let q = BigInteger::from_u32(13);
        let four = field_element(q.clone(), BigInteger::from_u32(4));
        assert_eq!(four.sqrt().unwrap().square().as_ref(), &BigInteger::from_u32(4));
        // 2 非剩餘 → None。
        assert!(field_element(q, BigInteger::from_u32(2)).sqrt().is_none());
    }

    #[test]
    fn sqrt_q_1_mod_8() {
        // GF(17)，17 ≡ 1 (mod 8) → Lucas 分支。QR = {1,2,4,8,9,13,15,16}。
        let q = BigInteger::from_u32(17);
        for v in [2u32, 4, 8, 9, 16] {
            let fe = field_element(q.clone(), BigInteger::from_u32(v));
            let root = fe.sqrt().unwrap_or_else(|| panic!("{v} 應為二次剩餘"));
            assert_eq!(root.square().as_ref(), &BigInteger::from_u32(v));
        }
        // 3 非剩餘 → None。
        assert!(field_element(q, BigInteger::from_u32(3)).sqrt().is_none());
    }

    #[test]
    fn invert_is_multiplicative_inverse() {
        let q = BigInteger::from_u32(7);
        // 3⁻¹ ≡ 5 (mod 7)，且 3 · 3⁻¹ = 1。
        let a = field_element(q.clone(), BigInteger::from_u32(3));
        assert_eq!(a.invert().as_ref(), &BigInteger::from_u32(5));
        assert!((&a * &a.invert()).is_one());

        // 大體域:a · a⁻¹ = 1。
        let q = secp256k1_prime();
        let a = field_element(q.clone(), &q - &BigInteger::from_u32(123456));
        assert!((&a * &a.invert()).is_one());
    }

    #[test]
    #[should_panic(expected = "not invertible")]
    fn invert_zero_panics() {
        let q = BigInteger::from_u32(7);
        field_element(q, BigInteger::from_u32(0)).invert();
    }

    #[test]
    fn add_one_wraps_at_q() {
        let q = BigInteger::from_u32(7);
        // 一般情形：3 + 1 = 4。
        let a = field_element(q.clone(), BigInteger::from_u32(3));
        assert_eq!(a.add_one().as_ref(), &BigInteger::from_u32(4));
        // 環繞：q−1 加一 → 0。
        let top = field_element(q, BigInteger::from_u32(6));
        assert!(top.add_one().is_zero());
    }

    #[test]
    fn mod_double_wraps_modulo_q() {
        let q = BigInteger::from_u32(7);
        let fe = field_element(q.clone(), BigInteger::from_u32(0));
        // 2·5 = 10 ≡ 3 (mod 7)；2·6 = 12 ≡ 5 (mod 7)。
        assert_eq!(fe.mod_double(&BigInteger::from_u32(5)), BigInteger::from_u32(3));
        assert_eq!(fe.mod_double(&BigInteger::from_u32(6)), BigInteger::from_u32(5));
        assert_eq!(fe.mod_double(&BigInteger::from_u32(3)), BigInteger::from_u32(6));
    }

    #[test]
    fn mod_half_abs_even_and_odd() {
        let q = BigInteger::from_u32(7);
        let fe = field_element(q, BigInteger::from_u32(0));
        // 偶：4/2 = 2、6/2 = 3。
        assert_eq!(fe.mod_half_abs(&BigInteger::from_u32(4)), BigInteger::from_u32(2));
        assert_eq!(fe.mod_half_abs(&BigInteger::from_u32(6)), BigInteger::from_u32(3));
        // 奇：(7−3)/2 = 2、(7−5)/2 = 1。
        assert_eq!(fe.mod_half_abs(&BigInteger::from_u32(3)), BigInteger::from_u32(2));
        assert_eq!(fe.mod_half_abs(&BigInteger::from_u32(5)), BigInteger::from_u32(1));
    }

    #[test]
    fn residue_small_prime_is_none() {
        // 位元長度 < 96 → 無快速形式。
        assert!(FpFieldElement::calculate_residue(&BigInteger::from_u32(97)).is_none());
    }

    // 對給定的 q，用一組測資交叉驗證 mod_reduce 與通用取模一致（含負數）。
    fn check_mod_reduce(q: &BigInteger) {
        let r = FpFieldElement::calculate_residue(q);
        let fe = FpFieldElement::new(q.clone(), BigInteger::from_u32(0), r);
        let samples = [
            q - &BigInteger::from_u32(1),
            q - &BigInteger::from_u32(12345),
            BigInteger::from_u32(2),
            q >> 1,
        ];
        for a in &samples {
            for b in &samples {
                let prod = a * b; // 可能接近 q²，涵蓋快速路徑主要輸入範圍
                assert_eq!(fe.mod_reduce(prod.clone()), prod.rem_euclid(q));
                let neg = -&prod;
                assert_eq!(fe.mod_reduce(neg.clone()), neg.rem_euclid(q));
            }
        }
        // 已在 [0, q) 的值：約簡應為原值。
        let inside = q - &BigInteger::from_u32(7);
        assert_eq!(fe.mod_reduce(inside.clone()), inside);
    }

    fn secp256k1_prime() -> BigInteger {
        BigInteger::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap()
    }

    #[test]
    fn mod_reduce_pseudo_mersenne_matches_generic() {
        // secp256k1：r > 0，走 pseudo-Mersenne 快速路徑。
        check_mod_reduce(&secp256k1_prime());
    }

    #[test]
    fn mod_reduce_barrett_matches_generic() {
        // NIST P-256：byte 對齊、頂端非全 1 → r < 0，走 Barrett 快速路徑。
        let p = BigInteger::from_str_radix(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            16,
        )
        .unwrap();
        check_mod_reduce(&p);
    }

    #[test]
    fn mod_reduce_generic_matches() {
        // 小質數：r == None，走通用取模路徑。
        check_mod_reduce(&BigInteger::from_u32(97));
    }
}
