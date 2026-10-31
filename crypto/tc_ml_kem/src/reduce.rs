/// 模數 q。
pub(crate) const Q: i16 = 3329;

/// q⁻¹ mod 2^16。
const Q_INV: i32 = 62209;

/// BC 的 `MontgomeryReduce`：a · 2^−16 mod q，結果在 (−q, q)；a 在 [−q · 2^15, q · 2^15)。
/// 常數時間：只有乘法、減法與位移。
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    let u = a.wrapping_mul(Q_INV) as i16;
    let t = i32::from(u) * i32::from(Q);
    (a.wrapping_sub(t) >> 16) as i16
}

/// BC 的 `BarrettReduce`：與 a 同餘、在 [0, q] 的值。常數時間：只有乘法、減法與位移。
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = ((1 << 26) + Q as i32 / 2) / Q as i32;
    let t = ((V * i32::from(a)) >> 26) as i16;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// BC 的 `CondSubQ`：a 不小於 q 時減去 q。常數時間：以符號位元當遮罩，不分支。
pub(crate) fn cond_sub_q(a: i16) -> i16 {
    let a = a.wrapping_sub(Q);
    a.wrapping_add((a >> 15) & Q)
}
