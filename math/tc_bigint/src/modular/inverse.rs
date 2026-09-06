//! Modular multiplicative inverse over fixed-width limbs.

#[cfg(feature = "alloc")]
use alloc::vec;

use super::mul::{fixed_mul_mod, fixed_one_mod, fixed_sub_mod};
use crate::Limb;
use crate::arithmetic::{fixed_div_rem, fixed_is_one, fixed_is_zero};

#[cfg(feature = "alloc")]
const M30: i32 = 0x3fff_ffff;

pub(crate) fn fixed_mod_inverse<const N: usize>(
    value: &[Limb; N],
    modulus: &[Limb; N],
) -> Option<[Limb; N]> {
    assert!(!fixed_is_zero(modulus), "modulus must be non-zero");
    let mut old_remainder = *modulus;
    let mut remainder = fixed_div_rem(value, modulus).1;
    let mut old_coefficient = [Limb(0); N];
    let mut coefficient = fixed_one_mod(modulus);

    while !fixed_is_zero(&remainder) {
        let (quotient, next_remainder) = fixed_div_rem(&old_remainder, &remainder);
        let product = fixed_mul_mod(&quotient, &coefficient, modulus);
        let next_coefficient = fixed_sub_mod(&old_coefficient, &product, modulus);
        old_remainder = remainder;
        remainder = next_remainder;
        old_coefficient = coefficient;
        coefficient = next_coefficient;
    }

    fixed_is_one(&old_remainder).then_some(old_coefficient)
}

/// `checked_mod_odd_inverse` 的輸入或可逆性錯誤。
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModOddInverseError {
    /// 模數、輸入與輸出 slice 的長度不相容。
    InvalidLength,
    /// 模數必須是正規化、非零的奇數。
    InvalidModulus,
    /// 輸入必須落在 `[0, modulus)`。
    ValueOutOfRange,
    /// 輸入與模數不互質，因此反元素不存在。
    NotInvertible,
}

/// 驗證輸入後，以固定步數 safegcd 計算奇模數反元素。
#[cfg(feature = "alloc")]
pub fn checked_mod_odd_inverse(
    modulus: &[u32],
    value: &[u32],
    output: &mut [u32],
) -> Result<(), ModOddInverseError> {
    check_mod_odd_inputs(modulus, value, output)?;
    if mod_odd_inverse(modulus, value, output) {
        Ok(())
    } else {
        Err(ModOddInverseError::NotInvertible)
    }
}

/// 驗證輸入後，以變動時間 safegcd 計算奇模數反元素。
///
/// 此版本的執行時間會洩漏輸入值，只能用於公開資料。
#[cfg(feature = "alloc")]
pub fn checked_mod_odd_inverse_var(
    modulus: &[u32],
    value: &[u32],
    output: &mut [u32],
) -> Result<(), ModOddInverseError> {
    check_mod_odd_inputs(modulus, value, output)?;
    if mod_odd_inverse_var(modulus, value, output) {
        Ok(())
    } else {
        Err(ModOddInverseError::NotInvertible)
    }
}

/// 以 Bernstein–Yang half-delta safegcd 計算奇模數反元素。
///
/// 迴圈次數只取決於公開的模數位元數；`value` 必須小於 `modulus`。
/// 回傳 `false` 表示反元素不存在。輸入與輸出採 little-endian 32-bit words。
#[cfg(feature = "alloc")]
pub fn mod_odd_inverse(modulus: &[u32], value: &[u32], output: &mut [u32]) -> bool {
    assert_mod_odd_inputs(modulus, value, output);

    let len32 = modulus.len();
    let bits = len32 * 32 - modulus[len32 - 1].leading_zeros() as usize;
    let len30 = bits.div_ceil(30);
    let mut d = vec![0_i32; len30];
    let mut e = vec![0_i32; len30];
    let mut f = vec![0_i32; len30];
    let mut g = vec![0_i32; len30];
    let mut m = vec![0_i32; len30];
    let mut t = [0_i32; 4];

    e[0] = 1;
    encode30(bits, value, &mut g);
    encode30(bits, modulus, &mut m);
    f.copy_from_slice(&m);

    let mut theta = 0;
    let m0_inverse = inverse32(m[0] as u32) as i32;
    let max_divsteps = maximum_half_delta_divsteps(bits);
    let mut divsteps = 0;
    while divsteps < max_divsteps {
        theta = half_delta_divsteps30(theta, f[0], g[0], &mut t);
        update_de30(&mut d, &mut e, &t, m0_inverse, &m);
        update_fg30(&mut f, &mut g, &t);
        divsteps += 30;
    }

    let sign_f = f[len30 - 1] >> 31;
    conditional_negate30(sign_f, &mut f);
    conditional_normalize30(sign_f, &mut d, &m);
    decode30(bits, &d, output);

    equal_to30(&f, 1) & equal_to30(&g, 0) != 0
}

/// 以變動時間 safegcd 計算奇模數反元素。
///
/// 此版本會依 `value` 提早結束，只能用於公開資料。其餘契約與
/// [`mod_odd_inverse`] 相同。
#[cfg(feature = "alloc")]
pub fn mod_odd_inverse_var(modulus: &[u32], value: &[u32], output: &mut [u32]) -> bool {
    assert_mod_odd_inputs(modulus, value, output);

    let len32 = modulus.len();
    let bits = len32 * 32 - modulus[len32 - 1].leading_zeros() as usize;
    let len30 = bits.div_ceil(30);
    let leading_zeros = bits - bit_length32(value);
    let mut d = vec![0_i32; len30];
    let mut e = vec![0_i32; len30];
    let mut f = vec![0_i32; len30];
    let mut g = vec![0_i32; len30];
    let mut m = vec![0_i32; len30];
    let mut t = [0_i32; 4];

    e[0] = 1;
    encode30(bits, value, &mut g);
    encode30(bits, modulus, &mut m);
    f.copy_from_slice(&m);

    let mut eta = -(leading_zeros as i32);
    let mut len_fg = len30;
    let m0_inverse = inverse32(m[0] as u32) as i32;
    let max_divsteps = maximum_divsteps(bits);
    let mut divsteps = leading_zeros;

    while !equal_to_var30(&g[..len_fg], 0) {
        if divsteps >= max_divsteps {
            return false;
        }
        divsteps += 30;
        eta = divsteps30_var(eta, f[0], g[0], &mut t);
        update_de30(&mut d, &mut e, &t, m0_inverse, &m);
        update_fg30(&mut f[..len_fg], &mut g[..len_fg], &t);
        len_fg = trim_fg30_var(len_fg, &mut f, &mut g);
    }

    let mut sign_f = f[len_fg - 1] >> 31;
    let mut sign_d = d[len30 - 1] >> 31;
    if sign_d < 0 {
        sign_d = add30(&mut d, &m);
    }
    if sign_f < 0 {
        sign_d = negate30(&mut d);
        sign_f = negate30(&mut f[..len_fg]);
    }
    debug_assert_eq!(sign_f, 0);
    if !equal_to_var30(&f[..len_fg], 1) {
        return false;
    }
    if sign_d < 0 {
        sign_d = add30(&mut d, &m);
    }
    debug_assert_eq!(sign_d, 0);
    decode30(bits, &d, output);
    true
}

/// 以固定步數 safegcd 判斷兩個數是否互質。
#[cfg(feature = "alloc")]
pub fn mod_odd_is_coprime(modulus: &[u32], value: &[u32]) -> bool {
    assert_mod_odd_pair(modulus, value);

    let len32 = modulus.len();
    let bits = len32 * 32 - modulus[len32 - 1].leading_zeros() as usize;
    let len30 = bits.div_ceil(30);
    let mut f = vec![0_i32; len30];
    let mut g = vec![0_i32; len30];
    let mut m = vec![0_i32; len30];
    let mut t = [0_i32; 4];
    encode30(bits, value, &mut g);
    encode30(bits, modulus, &mut m);
    f.copy_from_slice(&m);

    let mut theta = 0;
    let mut divsteps = 0;
    let max_divsteps = maximum_half_delta_divsteps(bits);
    while divsteps < max_divsteps {
        theta = half_delta_divsteps30(theta, f[0], g[0], &mut t);
        update_fg30(&mut f, &mut g, &t);
        divsteps += 30;
    }
    let sign_f = f[len30 - 1] >> 31;
    conditional_negate30(sign_f, &mut f);
    equal_to30(&f, 1) & equal_to30(&g, 0) != 0
}

/// 以變動時間 safegcd 判斷兩個數是否互質，只能用於公開資料。
#[cfg(feature = "alloc")]
pub fn mod_odd_is_coprime_var(modulus: &[u32], value: &[u32]) -> bool {
    assert_mod_odd_pair(modulus, value);

    let len32 = modulus.len();
    let bits = len32 * 32 - modulus[len32 - 1].leading_zeros() as usize;
    let len30 = bits.div_ceil(30);
    let leading_zeros = bits - bit_length32(value);
    let mut f = vec![0_i32; len30];
    let mut g = vec![0_i32; len30];
    let mut m = vec![0_i32; len30];
    let mut t = [0_i32; 4];
    encode30(bits, value, &mut g);
    encode30(bits, modulus, &mut m);
    f.copy_from_slice(&m);

    let mut eta = -(leading_zeros as i32);
    let mut len_fg = len30;
    let max_divsteps = maximum_divsteps(bits);
    let mut divsteps = leading_zeros;
    while !equal_to_var30(&g[..len_fg], 0) {
        if divsteps >= max_divsteps {
            return false;
        }
        divsteps += 30;
        eta = divsteps30_var(eta, f[0], g[0], &mut t);
        update_fg30(&mut f[..len_fg], &mut g[..len_fg], &t);
        len_fg = trim_fg30_var(len_fg, &mut f, &mut g);
    }
    if f[len_fg - 1] < 0 {
        negate30(&mut f[..len_fg]);
    }
    equal_to_var30(&f[..len_fg], 1)
}

#[cfg(feature = "alloc")]
fn check_mod_odd_inputs(
    modulus: &[u32],
    value: &[u32],
    output: &[u32],
) -> Result<(), ModOddInverseError> {
    if modulus.is_empty() || value.len() != modulus.len() || output.len() < modulus.len() {
        return Err(ModOddInverseError::InvalidLength);
    }
    if modulus[0] & 1 == 0 || modulus[modulus.len() - 1] == 0 {
        return Err(ModOddInverseError::InvalidModulus);
    }
    if cmp32(value, modulus) != core::cmp::Ordering::Less {
        return Err(ModOddInverseError::ValueOutOfRange);
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn assert_mod_odd_pair(modulus: &[u32], value: &[u32]) {
    assert!(!modulus.is_empty(), "modulus must not be empty");
    assert_eq!(
        value.len(),
        modulus.len(),
        "value length must match modulus"
    );
    assert!(modulus[0] & 1 != 0, "modulus must be odd");
    assert!(
        modulus[modulus.len() - 1] != 0,
        "modulus must be normalized"
    );
    assert!(
        cmp32(value, modulus) == core::cmp::Ordering::Less,
        "value must be smaller than modulus"
    );
}

#[cfg(feature = "alloc")]
fn assert_mod_odd_inputs(modulus: &[u32], value: &[u32], output: &[u32]) {
    assert_mod_odd_pair(modulus, value);
    assert!(
        output.len() >= modulus.len(),
        "output must have at least modulus length"
    );
}

#[cfg(feature = "alloc")]
fn cmp32(lhs: &[u32], rhs: &[u32]) -> core::cmp::Ordering {
    lhs.iter().rev().cmp(rhs.iter().rev())
}

#[cfg(feature = "alloc")]
fn bit_length32(value: &[u32]) -> usize {
    value
        .iter()
        .rposition(|word| *word != 0)
        .map_or(0, |index| {
            index * 32 + (32 - value[index].leading_zeros()) as usize
        })
}

#[cfg(feature = "alloc")]
fn inverse32(value: u32) -> u32 {
    debug_assert_eq!(value & 1, 1);
    let mut inverse = value;
    for _ in 0..4 {
        inverse = inverse.wrapping_mul(2_u32.wrapping_sub(value.wrapping_mul(inverse)));
    }
    debug_assert_eq!(value.wrapping_mul(inverse), 1);
    inverse
}

#[cfg(feature = "alloc")]
fn add30(value: &mut [i32], modulus: &[i32]) -> i32 {
    let last = value.len() - 1;
    let mut carry = 0_i64;
    for index in 0..last {
        carry += i64::from(value[index]) + i64::from(modulus[index]);
        value[index] = carry as i32 & M30;
        carry >>= 30;
    }
    carry += i64::from(value[last]) + i64::from(modulus[last]);
    value[last] = carry as i32;
    (carry >> 30) as i32
}

#[cfg(feature = "alloc")]
fn conditional_negate30(condition: i32, value: &mut [i32]) {
    let last = value.len() - 1;
    let mut carry = 0_i64;
    for word in &mut value[..last] {
        carry += i64::from((*word ^ condition).wrapping_sub(condition));
        *word = carry as i32 & M30;
        carry >>= 30;
    }
    carry += i64::from((value[last] ^ condition).wrapping_sub(condition));
    value[last] = carry as i32;
}

#[cfg(feature = "alloc")]
fn conditional_normalize30(condition_negate: i32, value: &mut [i32], modulus: &[i32]) {
    let last = value.len() - 1;
    let mut carry = 0_i64;
    let condition_add = value[last] >> 31;
    for index in 0..last {
        let word = value[index].wrapping_add(modulus[index] & condition_add);
        let word = (word ^ condition_negate).wrapping_sub(condition_negate);
        carry += i64::from(word);
        value[index] = carry as i32 & M30;
        carry >>= 30;
    }
    let word = value[last].wrapping_add(modulus[last] & condition_add);
    let word = (word ^ condition_negate).wrapping_sub(condition_negate);
    carry += i64::from(word);
    value[last] = carry as i32;

    carry = 0;
    let condition_add = value[last] >> 31;
    for index in 0..last {
        carry += i64::from(value[index].wrapping_add(modulus[index] & condition_add));
        value[index] = carry as i32 & M30;
        carry >>= 30;
    }
    carry += i64::from(value[last].wrapping_add(modulus[last] & condition_add));
    value[last] = carry as i32;
    debug_assert_eq!(carry >> 30, 0);
}

#[cfg(feature = "alloc")]
fn decode30(mut bits: usize, value: &[i32], output: &mut [u32]) {
    output.fill(0);
    let mut available = 0_i32;
    let mut data = 0_u64;
    let mut input = 0;
    let mut out = 0;
    while bits > 0 {
        while available < 32.min(bits) as i32 {
            data |= (value[input] as u32 as u64) << available as u32;
            input += 1;
            available += 30;
        }
        output[out] = data as u32;
        out += 1;
        data >>= 32;
        available -= 32;
        bits = bits.saturating_sub(32);
    }
}

#[cfg(feature = "alloc")]
fn divsteps30_var(mut eta: i32, f0: i32, g0: i32, t: &mut [i32; 4]) -> i32 {
    let (mut u, mut v, mut q, mut r) = (1_i32, 0_i32, 0_i32, 1_i32);
    let (mut f, mut g) = (f0, g0);
    let mut remaining = 30_u32;
    loop {
        let sentinel = (-1_i32).wrapping_shl(remaining);
        let zeros = (g | sentinel).trailing_zeros();
        g >>= zeros;
        u = u.wrapping_shl(zeros);
        v = v.wrapping_shl(zeros);
        eta -= zeros as i32;
        remaining -= zeros;
        if remaining == 0 {
            break;
        }

        if eta <= 0 {
            eta = 2 - eta;
            let old_f = f;
            f = g;
            g = old_f.wrapping_neg();
            let old_u = u;
            u = q;
            q = old_u.wrapping_neg();
            let old_v = v;
            v = r;
            r = old_v.wrapping_neg();

            let limit = (eta as u32).min(remaining);
            let mask = ((u32::MAX >> (32 - limit)) & 63) as i32;
            let f_squared_minus_two = f.wrapping_mul(f).wrapping_sub(2);
            let multiplier = f.wrapping_mul(g).wrapping_mul(f_squared_minus_two) & mask;
            g = g.wrapping_add(f.wrapping_mul(multiplier));
            q = q.wrapping_add(u.wrapping_mul(multiplier));
            r = r.wrapping_add(v.wrapping_mul(multiplier));
        } else {
            let limit = (eta as u32).min(remaining);
            let mask = ((u32::MAX >> (32 - limit)) & 15) as i32;
            let adjusted_f = f.wrapping_add((f.wrapping_add(1) & 4) << 1);
            let multiplier = adjusted_f.wrapping_mul(g.wrapping_neg()) & mask;
            g = g.wrapping_add(f.wrapping_mul(multiplier));
            q = q.wrapping_add(u.wrapping_mul(multiplier));
            r = r.wrapping_add(v.wrapping_mul(multiplier));
        }
    }
    *t = [u, v, q, r];
    eta
}

#[cfg(feature = "alloc")]
fn encode30(mut bits: usize, value: &[u32], output: &mut [i32]) {
    let mut available = 0_i32;
    let mut data = 0_u64;
    let mut input = 0;
    let mut out = 0;
    while bits > 0 {
        if available < 30.min(bits) as i32 {
            data |= u64::from(value[input]) << available as u32;
            input += 1;
            available += 32;
        }
        output[out] = data as i32 & M30;
        out += 1;
        data >>= 30;
        available -= 30;
        bits = bits.saturating_sub(30);
    }
}

#[cfg(feature = "alloc")]
fn equal_to30(value: &[i32], expected: i32) -> i32 {
    let mut difference = value[0] ^ expected;
    for word in &value[1..] {
        difference |= *word;
    }
    let bits = difference as u32;
    ((bits | bits.wrapping_neg()) >> 31) as i32 ^ 1
}

#[cfg(feature = "alloc")]
fn equal_to_var30(value: &[i32], expected: i32) -> bool {
    value[0] == expected && value[1..].iter().all(|word| *word == 0)
}

#[cfg(feature = "alloc")]
fn maximum_divsteps(bits: usize) -> usize {
    ((188_898_u64 * bits as u64 + if bits < 46 { 308_405 } else { 181_188 }) >> 16) as usize
}

#[cfg(feature = "alloc")]
fn maximum_half_delta_divsteps(bits: usize) -> usize {
    ((150_964_u64 * bits as u64 + 99_243) >> 16) as usize
}

#[cfg(feature = "alloc")]
fn half_delta_divsteps30(mut theta: i32, f0: i32, g0: i32, t: &mut [i32; 4]) -> i32 {
    let (mut u, mut v, mut q, mut r) = (1_i32 << 30, 0_i32, 0_i32, 1_i32 << 30);
    let (mut f, mut g) = (f0, g0);
    for _ in 0..30 {
        let c1 = theta >> 31;
        let c2 = -(g & 1);
        let x = f ^ c1;
        let y = u ^ c1;
        let z = v ^ c1;
        g = g.wrapping_sub(x & c2);
        q = q.wrapping_sub(y & c2);
        r = r.wrapping_sub(z & c2);
        let c3 = c2 & !c1;
        theta = (theta ^ c3).wrapping_add(1);
        f = f.wrapping_add(g & c3);
        u = u.wrapping_add(q & c3);
        v = v.wrapping_add(r & c3);
        g >>= 1;
        q >>= 1;
        r >>= 1;
    }
    *t = [u, v, q, r];
    theta
}

#[cfg(feature = "alloc")]
fn negate30(value: &mut [i32]) -> i32 {
    let last = value.len() - 1;
    let mut carry = 0_i64;
    for word in &mut value[..last] {
        carry -= i64::from(*word);
        *word = carry as i32 & M30;
        carry >>= 30;
    }
    carry -= i64::from(value[last]);
    value[last] = carry as i32;
    (carry >> 30) as i32
}

#[cfg(feature = "alloc")]
fn trim_fg30_var(mut len: usize, f: &mut [i32], g: &mut [i32]) -> usize {
    if len > 1 {
        let f_high = f[len - 1];
        let g_high = g[len - 1];
        if (f_high ^ (f_high >> 31)) | (g_high ^ (g_high >> 31)) == 0 {
            f[len - 2] |= f_high << 30;
            g[len - 2] |= g_high << 30;
            len -= 1;
        }
    }
    len
}

#[cfg(feature = "alloc")]
fn update_de30(
    d: &mut [i32],
    e: &mut [i32],
    transform: &[i32; 4],
    m0_inverse: i32,
    modulus: &[i32],
) {
    let [u, v, q, r] = *transform;
    let sign_d = d[d.len() - 1] >> 31;
    let sign_e = e[e.len() - 1] >> 31;
    let mut md = (u & sign_d).wrapping_add(v & sign_e);
    let mut me = (q & sign_d).wrapping_add(r & sign_e);
    let mut carry_d = i64::from(u) * i64::from(d[0]) + i64::from(v) * i64::from(e[0]);
    let mut carry_e = i64::from(q) * i64::from(d[0]) + i64::from(r) * i64::from(e[0]);
    md = md.wrapping_sub(m0_inverse.wrapping_mul(carry_d as i32).wrapping_add(md) & M30);
    me = me.wrapping_sub(m0_inverse.wrapping_mul(carry_e as i32).wrapping_add(me) & M30);
    carry_d += i64::from(modulus[0]) * i64::from(md);
    carry_e += i64::from(modulus[0]) * i64::from(me);
    debug_assert_eq!(carry_d as i32 & M30, 0);
    debug_assert_eq!(carry_e as i32 & M30, 0);
    carry_d >>= 30;
    carry_e >>= 30;

    for index in 1..d.len() {
        carry_d += i64::from(u) * i64::from(d[index])
            + i64::from(v) * i64::from(e[index])
            + i64::from(modulus[index]) * i64::from(md);
        carry_e += i64::from(q) * i64::from(d[index])
            + i64::from(r) * i64::from(e[index])
            + i64::from(modulus[index]) * i64::from(me);
        d[index - 1] = carry_d as i32 & M30;
        e[index - 1] = carry_e as i32 & M30;
        carry_d >>= 30;
        carry_e >>= 30;
    }
    let last = d.len() - 1;
    d[last] = carry_d as i32;
    e[last] = carry_e as i32;
}

#[cfg(feature = "alloc")]
fn update_fg30(f: &mut [i32], g: &mut [i32], transform: &[i32; 4]) {
    let [u, v, q, r] = *transform;
    let mut carry_f = i64::from(u) * i64::from(f[0]) + i64::from(v) * i64::from(g[0]);
    let mut carry_g = i64::from(q) * i64::from(f[0]) + i64::from(r) * i64::from(g[0]);
    debug_assert_eq!(carry_f as i32 & M30, 0);
    debug_assert_eq!(carry_g as i32 & M30, 0);
    carry_f >>= 30;
    carry_g >>= 30;
    for index in 1..f.len() {
        carry_f += i64::from(u) * i64::from(f[index]) + i64::from(v) * i64::from(g[index]);
        carry_g += i64::from(q) * i64::from(f[index]) + i64::from(r) * i64::from(g[index]);
        f[index - 1] = carry_f as i32 & M30;
        g[index - 1] = carry_g as i32 & M30;
        carry_f >>= 30;
        carry_g >>= 30;
    }
    let last = f.len() - 1;
    f[last] = carry_f as i32;
    g[last] = carry_g as i32;
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::{BigUint, ModMul};

    #[test]
    fn odd_inverse_known_values_and_non_coprime_inputs() {
        let mut output = [0_u32; 1];
        assert!(mod_odd_inverse(&[7], &[3], &mut output));
        assert_eq!(output, [5]);
        assert!(mod_odd_inverse_var(&[7], &[3], &mut output));
        assert_eq!(output, [5]);
        assert!(mod_odd_is_coprime(&[7], &[3]));
        assert!(mod_odd_is_coprime_var(&[7], &[3]));

        assert!(!mod_odd_inverse(&[15], &[6], &mut output));
        assert!(!mod_odd_inverse_var(&[15], &[6], &mut output));
        assert!(!mod_odd_is_coprime(&[15], &[6]));
        assert!(!mod_odd_is_coprime_var(&[15], &[6]));
        assert_eq!(
            checked_mod_odd_inverse(&[15], &[6], &mut output),
            Err(ModOddInverseError::NotInvertible)
        );
    }

    #[test]
    fn checked_odd_inverse_rejects_invalid_contracts() {
        let mut output = [0_u32; 1];
        assert_eq!(
            checked_mod_odd_inverse(&[], &[], &mut []),
            Err(ModOddInverseError::InvalidLength)
        );
        assert_eq!(
            checked_mod_odd_inverse(&[8], &[3], &mut output),
            Err(ModOddInverseError::InvalidModulus)
        );
        assert_eq!(
            checked_mod_odd_inverse(&[7], &[7], &mut output),
            Err(ModOddInverseError::ValueOutOfRange)
        );
    }

    #[test]
    fn constant_time_and_variable_time_inverse_match_biguint() {
        let mut state = 0xC0DE_CAFE_5AFE_6CD1_u64;
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let modulus_value = state | (1_u64 << 63) | 1;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value_value = state % modulus_value;
            let modulus = [modulus_value as u32, (modulus_value >> 32) as u32];
            let value = [value_value as u32, (value_value >> 32) as u32];
            let mut constant_time = [0_u32; 2];
            let mut variable_time = [0_u32; 2];
            let constant_success = mod_odd_inverse(&modulus, &value, &mut constant_time);
            let variable_success = mod_odd_inverse_var(&modulus, &value, &mut variable_time);
            let modulus_big = BigUint::from(modulus_value);
            let value_big = BigUint::from(value_value);
            let expected = value_big.mod_inverse(&modulus_big);

            assert_eq!(constant_success, expected.is_some());
            assert_eq!(variable_success, expected.is_some());
            assert_eq!(mod_odd_is_coprime(&modulus, &value), expected.is_some());
            assert_eq!(mod_odd_is_coprime_var(&modulus, &value), expected.is_some());
            if let Some(expected) = expected {
                assert_eq!(constant_time, variable_time);
                let inverse = BigUint::from_le_u32(&constant_time);
                assert_eq!(inverse, expected);
                assert_eq!(
                    value_big.mod_mul(&inverse, &modulus_big),
                    BigUint::from(1_u8)
                );
            }
        }
    }

    #[test]
    fn p256_inverse_satisfies_the_field_identity() {
        let modulus = [
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0,
            0,
            0,
            1,
            0xffff_ffff,
        ];
        let value = [
            0x89ab_cdef,
            0x0123_4567,
            0x7654_3211,
            0xfedc_ba98,
            0x55aa_00ff,
            0x1020_3040,
            0x3141_5926,
            0x2718_2818,
        ];
        let mut constant_time = [0_u32; 8];
        let mut variable_time = [0_u32; 8];
        assert!(mod_odd_inverse(&modulus, &value, &mut constant_time));
        assert!(mod_odd_inverse_var(&modulus, &value, &mut variable_time));
        assert_eq!(constant_time, variable_time);

        let modulus_big = BigUint::from_le_u32(&modulus);
        let value_big = BigUint::from_le_u32(&value);
        let inverse_big = BigUint::from_le_u32(&constant_time);
        assert_eq!(
            value_big.mod_mul(&inverse_big, &modulus_big),
            BigUint::from(1_u8)
        );
    }
}
