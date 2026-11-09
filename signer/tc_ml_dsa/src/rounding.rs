use crate::poly::{D, Q};

/// BC 的 `Power2Round`：a = a1·2ᵈ + a0，回傳 (a1, a0)，−2ᵈ⁻¹ < a0 ≤ 2ᵈ⁻¹。常數時間。
pub(crate) fn power2round(a: i32) -> (i32, i32) {
    const U: i32 = (1 << (D - 1)) - 1;
    const V: i32 = -1 << D;
    let t = a + U;
    (t >> D, a - (t & V))
}

/// BC 的 `Decompose`：a = a1·2γ2 + a0，回傳 (a1, a0)。常數時間。
pub(crate) fn decompose(a: i32, gamma2: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;
    if gamma2 == (Q - 1) / 32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    let mut a0 = a - a1 * 2 * gamma2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a1, a0)
}

/// BC 的 `MakeHint`：a0 的進位會不會改變高位元。常數時間。
pub(crate) fn make_hint(a0: i32, a1: i32, gamma2: i32) -> i32 {
    let t = Q - gamma2 - a0;
    let u = t | a1;
    (((gamma2 - a0) & !t & (u | u.wrapping_neg())) >> 31) & 1
}

/// BC 的 `UseHint`：依提示修正高位元。變動時間：只用在驗章的公開值上。
pub(crate) fn use_hint(a: i32, hint: i32, gamma2: i32) -> i32 {
    let (a1, a0) = decompose(a, gamma2);
    if hint == 0 {
        return a1;
    }
    if gamma2 == (Q - 1) / 32 {
        if a0 > 0 { (a1 + 1) & 15 } else { (a1 - 1) & 15 }
    } else if a0 > 0 {
        if a1 == 43 { 0 } else { a1 + 1 }
    } else if a1 == 0 {
        43
    } else {
        a1 - 1
    }
}
