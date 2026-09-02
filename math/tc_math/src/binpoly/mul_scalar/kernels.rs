//! Scalar (non-SIMD) carryless-multiply kernels for `GF(2)[x]`.
//!
//! Ported from Bouncy Castle's `Math.BinPoly.Scalar.Kernels`. The leaf multiply
//! ([`impl_mul`]) is a Karatsuba-style schoolbook whose 1×1 step ([`clmul64`]) is
//! a 16-entry-table carryless `u64 × u64 → 128-bit`. Karatsuba recursion for large
//! operands (bc's `Large`) is a later addition; the leaf alone covers every NIST
//! binary curve below sect571 (`size < 8` limbs).
//!
//! bc's `ulong[] + int offset` surface becomes slice arguments here: the leaf
//! takes disjoint `x` / `y` (`len` limbs) and writes the `2·len`-limb product into
//! `zz`.

/// 1×1 carryless multiply of `x` and `y` over `GF(2)`: returns the low and high
/// 64-bit halves `(lo, hi)` of the 128-bit product. Replaces bc's `ImplMulw`
/// (overwrite) and `ImplMulwAcc` (the caller XORs the halves to accumulate).
fn clmul64(x: u64, y: u64) -> (u64, u64) {
    // 16-entry 表格 u：u[j] = (j · y) 的低 64 位（carryless）。
    // u[0] 恆為 0（靠零初始化、從不寫入），是「nibble=0 → 0」查表的前提。
    let mut u = [0u64; 16];
    u[1] = y;

    // h 累積高位；m/n 是 x/y 的滾動副本，供交錯進來的「高位修正」步。
    let mut h: u64 = 0;
    let mut m = x;
    let mut n = y;

    for i in (2usize..16).step_by(2) {
        let u_i = u[i / 2] << 1; // 倍化：u[2k] = 2·u[k]（丟掉的高位由 h 修正）
        u[i] = u_i;
        u[i + 1] = u_i ^ y; // u[2k+1] = u[2k] ^ y

        // 交錯的高位修正（bc 放這是為了效能）：
        m = (m & 0xFEFE_FEFE_FEFE_FEFE) >> 1;
        h ^= m & ((n as i64 >> 63) as u64); // n 最高位 → 全 1 / 全 0 遮罩（算術右移）
        n <<= 1;
    }

    // 最低位元組（k=0）：只貢獻 l，不貢獻 h（g >> 64 = 0，故單獨處理、省掉非法位移）。
    let mut j = x as u32;
    let mut l = u[(j & 15) as usize] ^ (u[((j >> 4) & 15) as usize] << 4);

    // 其餘 7 個位元組：k = 56, 48, …, 8。
    for step in 0..7u32 {
        let k = 56 - step * 8;
        j = (x >> k) as u32;
        let g = u[(j & 15) as usize] ^ (u[((j >> 4) & 15) as usize] << 4);
        l ^= g << k;
        h ^= g >> (64 - k); // bc 的 g >> -k：C# 對 ulong 位移取低 6 位 → 等於 >> (64-k)
    }

    debug_assert_eq!(h >> 63, 0);
    (l, h)
}

/// Leaf carryless multiply: `zz = x * y` in `GF(2)[x]`, **no reduction**. `x` and
/// `y` are `len` limbs; `zz` is `2·len` limbs and is overwritten. The three slices
/// must be disjoint.
///
/// Ported from bc `Kernels.ImplMul` (diagonal products `xᵢyᵢ` plus symmetric
/// cross-products `(xₗₒ⊕xₕᵢ)(yₗₒ⊕yₕᵢ)`).
pub(crate) fn impl_mul(x: &[u64], y: &[u64], zz: &mut [u64]) {
    debug_assert_eq!(x.len(), y.len());
    debug_assert_eq!(zz.len(), 2 * x.len());
    let len = x.len();

    // 對角相：zz[2i], zz[2i+1] = xᵢ·yᵢ（覆寫）
    for i in 0..len {
        let (lo, hi) = clmul64(x[i], y[i]);
        zz[2 * i] = lo;
        zz[2 * i + 1] = hi;
    }

    impl_mul_postprocess(x, y, zz);
}

/// 交叉項後處理（bc `ImplMulPostprocess`）：對角摺疊 + 高半段廣播 + 上三角交叉項。
///
/// 逐行機械翻譯自 bc；正確性靠對照獨立 schoolbook 的 fuzz 測試把關。
fn impl_mul_postprocess(x: &[u64], y: &[u64], zz: &mut [u64]) {
    let len = x.len();

    // 對角摺疊（v0/v1 streak）：讀 zz[2i]/zz[2i+1]，寫 zz[i]
    let mut v0 = zz[0];
    let mut v1 = zz[1];
    for i in 1..len {
        v0 ^= zz[2 * i];
        zz[i] = v0 ^ v1;
        v1 ^= zz[2 * i + 1];
    }

    // 高半段 = 低半段 XOR (w 廣播)：zz[len+i] = zz[i] ^ w（bc 的 Nat.Xor64 純量廣播）
    let w = v0 ^ v1;
    for i in 0..len {
        zz[len + i] = zz[i] ^ w;
    }

    // 上三角交叉項：對 lo+hi=z_pos, lo<hi 累加 (xₗₒ⊕xₕᵢ)(yₗₒ⊕yₕᵢ)
    let last = len - 1;
    for z_pos in 1..(last * 2) {
        let mut hi = last.min(z_pos);
        let mut lo = z_pos - hi;
        while lo < hi {
            let (l, h) = clmul64(x[lo] ^ x[hi], y[lo] ^ y[hi]);
            zz[z_pos] ^= l;
            zz[z_pos + 1] ^= h;
            lo += 1;
            hi -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 獨立的參考實作：逐位元 carryless 乘法（128 位結果，回傳 (lo, hi)）。
    fn clmul64_ref(x: u64, y: u64) -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for i in 0..64u32 {
            if (x >> i) & 1 == 1 {
                lo ^= y << i;
                if i != 0 {
                    hi ^= y >> (64 - i);
                }
            }
        }
        (lo, hi)
    }

    #[test]
    fn clmul64_special_cases() {
        assert_eq!(clmul64(0, 0xDEAD_BEEF), (0, 0)); // 0·y = 0
        assert_eq!(clmul64(1, 0xDEAD_BEEF), (0xDEAD_BEEF, 0)); // 1·y = y
        assert_eq!(clmul64(0xDEAD_BEEF, 1), (0xDEAD_BEEF, 0)); // x·1 = x
        // x = 2（bit1）→ 積 = y << 1
        let y = 0x8000_0000_0000_00FFu64;
        assert_eq!(clmul64(2, y), (y << 1, y >> 63));
        // 2^63 · 2^63 = 2^126 → hi bit 62
        assert_eq!(clmul64(1 << 63, 1 << 63), (0, 1 << 62));
    }

    #[test]
    fn clmul64_matches_reference_fuzz() {
        // xorshift64 決定性亂數，對照獨立參考實作
        let mut s = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..20_000 {
            let x = next();
            let y = next();
            assert_eq!(clmul64(x, y), clmul64_ref(x, y), "x={x:#018x} y={y:#018x}");
        }
    }

    #[test]
    fn clmul64_is_commutative() {
        let mut s = 0x0FED_CBA9_8765_4321u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..5_000 {
            let x = next();
            let y = next();
            assert_eq!(clmul64(x, y), clmul64(y, x), "x={x:#018x} y={y:#018x}");
        }
    }

    /// 獨立參考：裸 schoolbook carryless 多項式乘法（len² 個 1×1，用 clmul64_ref）。
    fn poly_mul_ref(x: &[u64], y: &[u64]) -> Vec<u64> {
        let len = x.len();
        let mut zz = vec![0u64; 2 * len];
        for i in 0..len {
            for j in 0..len {
                let (lo, hi) = clmul64_ref(x[i], y[j]);
                zz[i + j] ^= lo;
                zz[i + j + 1] ^= hi;
            }
        }
        zz
    }

    #[test]
    fn impl_mul_matches_schoolbook_fuzz() {
        // xorshift64 決定性亂數；各 len 對照獨立 schoolbook
        let mut s = 0xC0FF_EE12_3456_789Au64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for len in 1..=6usize {
            for _ in 0..2_000 {
                let x: Vec<u64> = (0..len).map(|_| next()).collect();
                let y: Vec<u64> = (0..len).map(|_| next()).collect();
                let mut zz = vec![0u64; 2 * len];
                impl_mul(&x, &y, &mut zz);
                assert_eq!(zz, poly_mul_ref(&x, &y), "len={len}");
            }
        }
    }
}
