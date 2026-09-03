//! Itoh–Tsujii multiplicative inversion in `GF(2ⁿ)` — bc `ItohTsujiiInv`.
//!
//! Computes `a⁻¹ = a^(2ⁿ - 2) = (a^(2ⁿ⁻¹ - 1))²` via a binary addition chain on the
//! exponent `e = n - 1`, driving a [`BinPolyMul`]'s `square_n` / `square` /
//! `multiply` (so it is backend-independent — one implementation serves every ISA).
//! Correct only for an irreducible reduction polynomial (a genuine field).

use alloc::boxed::Box;
use alloc::vec;

use crate::binpoly::inv::BinPolyInv;
use crate::binpoly::mul::BinPolyMul;

/// Let `a_k = a^(2^k - 1)` (the element whose exponent has `k` one-bits). The chain
/// walks the bits of `e = n - 1` from below the MSB down to bit 0:
/// **double** (`k → 2k`): `a_{2k} = (a_k)^(2^k) · a_k`; **increment** (`k → k+1`,
/// when the bit is set): `a_{k+1} = (a_k)² · a`. A final square yields `a^(2ⁿ - 2)`.
///
/// Control flow branches only on `e` (the public field degree), never on element
/// data; `0` and `1` are fixed points of the primitives, so `invert(0) = 0` and
/// `invert(1) = 1` fall out with no special case.
struct ItohTsujiiInv {
    mul: Box<dyn BinPolyMul>,
    n: usize,
    size: usize,
}

impl BinPolyInv for ItohTsujiiInv {
    fn n(&self) -> usize {
        self.n
    }

    fn size(&self) -> usize {
        self.size
    }

    fn invert(&self, x: &[u64], z: &mut [u64]) {
        let size = self.size;
        debug_assert_eq!(x.len(), size);
        debug_assert_eq!(z.len(), size);
        let mul = &*self.mul;

        // b = a_j = a^(2^j - 1)；t = Frobenius 次方；tmp = 乘法/平方輸出 scratch。
        // （bc 就地改寫 b；Rust 借用不允許 x 與 z 相交，故用 scratch + swap 代替。）
        let mut b = x.to_vec(); // b = a = a_1
        let mut t = vec![0u64; size];
        let mut tmp = vec![0u64; size];

        let e = self.n - 1;
        let mut j = 1usize;
        let bl = (usize::BITS - e.leading_zeros()) as usize; // e 的位元長度
        for i in (0..bl.saturating_sub(1)).rev() {
            // double：a_{2j} = (a_j)^(2^j) · a_j
            mul.square_n(&b, j, &mut t); // t = b^(2^j)
            mul.multiply(&b, &t, &mut tmp); // tmp = b · t
            core::mem::swap(&mut b, &mut tmp); // b = b · t
            j <<= 1;

            if (e >> i) & 1 == 1 {
                // increment：a_{j+1} = (a_j)² · a
                mul.square(&b, &mut tmp); // tmp = b²
                mul.multiply(&tmp, x, &mut b); // b = b² · a
                j += 1;
            }
        }
        debug_assert_eq!(j, e);

        mul.square(&b, z); // z = b² = a^(2ⁿ - 2) = a⁻¹
    }
}

/// Builds an Itoh–Tsujii inverter over the field the given multiplier operates on.
/// Mirrors bc `BinPolys.Inv.ItohTsujii(mul)`.
pub fn create(mul: Box<dyn BinPolyMul>) -> Box<dyn BinPolyInv> {
    let (n, size) = (mul.n(), mul.size());
    debug_assert!(n >= 2);
    Box::new(ItohTsujiiInv { mul, n, size })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binpoly::{mul_scalar, reduce_pentanomial, reduce_trinomial, size};

    fn is_one(v: &[u64]) -> bool {
        v.first() == Some(&1) && v[1..].iter().all(|&w| w == 0)
    }
    fn is_zero(v: &[u64]) -> bool {
        v.iter().all(|&w| w == 0)
    }

    fn make_mul(n: usize, taps: &[usize]) -> Box<dyn BinPolyMul> {
        match *taps {
            [k] => mul_scalar::create(n, reduce_trinomial::create(n, k)),
            [k1, k2, k3] => mul_scalar::create(n, reduce_pentanomial::create(n, k1, k2, k3)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn invert_fixed_points() {
        // GF(2^233), 三項式；invert(0)=0、invert(1)=1
        let (n, taps): (usize, &[usize]) = (233, &[74]);
        let inv = create(make_mul(n, taps));
        let sz = size(n);
        let mut z = vec![0u64; sz];

        inv.invert(&vec![0u64; sz], &mut z);
        assert!(is_zero(&z), "invert(0) 應為 0");

        let mut one = vec![0u64; sz];
        one[0] = 1;
        inv.invert(&one, &mut z);
        assert!(is_one(&z), "invert(1) 應為 1");
    }

    #[test]
    fn invert_times_self_is_one_fuzz() {
        // 真實 SECT 體；隨機非零 a，驗 a · a⁻¹ == 1
        let cases: &[(usize, &[usize])] = &[
            (233, &[74]),       // sect233 trinomial
            (409, &[87]),       // sect409 trinomial
            (163, &[3, 6, 7]),  // sect163k1 pentanomial
            (283, &[5, 7, 12]), // sect283 pentanomial
        ];
        let mut s = 0xBEEF_1234_5678_9ABCu64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for &(n, taps) in cases {
            let sz = size(n);
            let inv = create(make_mul(n, taps));
            let mul = make_mul(n, taps); // 另一個 mul 供驗證（inv 已吃掉一個）
            for _ in 0..50 {
                let mut a: Vec<u64> = (0..sz).map(|_| next()).collect();
                let sbits = n % 64;
                if sbits != 0 {
                    let top = sz - 1;
                    a[top] &= !(u64::MAX << sbits); // 遮成 degree < n
                }
                if is_zero(&a) {
                    continue; // 跳過 0（無反元素）
                }
                let mut z = vec![0u64; sz];
                inv.invert(&a, &mut z);
                let mut prod = vec![0u64; sz];
                mul.multiply(&a, &z, &mut prod);
                assert!(is_one(&prod), "n={n}: a·a⁻¹ ≠ 1");
            }
        }
    }
}
