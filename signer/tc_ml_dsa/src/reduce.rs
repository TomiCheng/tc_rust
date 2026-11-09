use crate::poly::Q;

const Q_INV: i64 = 58728449;

/// BC 的 `MontgomeryReduce`：a·2⁻³² mod q，|a| ≤ 2³¹·q。常數時間。
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    let t = a.wrapping_mul(Q_INV) as i32;
    ((a - i64::from(t) * i64::from(Q)) >> 32) as i32
}

/// BC 的 `Reduce32`：約簡到 −6283009 ≤ r ≤ 6283008。常數時間。
pub(crate) fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// BC 的 `ConditionalAddQ`：負數加 q。常數時間。
pub(crate) fn conditional_add_q(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}
