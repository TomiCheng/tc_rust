//! RSA 核心運算的後端實作。

mod fixed;

/// limb 的位元寬度；`tc_bigint` 不公開字寬，這裡自行推導。
#[cfg(target_pointer_width = "64")]
const LIMB_BITS: usize = 64;
#[cfg(not(target_pointer_width = "64"))]
const LIMB_BITS: usize = 32;

/// 容納 `bits` 位元所需的 limb 數。
pub(crate) const fn limbs_for_bits(bits: usize) -> usize {
    bits.div_ceil(LIMB_BITS)
}

/// 大端序位元組所代表的位元長度；全零（含空切片）回 0。
pub(crate) fn bit_length(bytes: &[u8]) -> usize {
    let mut rest = bytes.iter().skip_while(|byte| **byte == 0);
    match rest.next() {
        None => 0,
        Some(top) => (8 - top.leading_zeros() as usize) + rest.count() * 8,
    }
}

/// 位元組是否代表零；空切片視為零。
pub(crate) fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// 位元組代表的整數是否為奇數；空切片是零，因此為偶數。
pub(crate) fn is_odd(bytes: &[u8]) -> bool {
    bytes.last().is_some_and(|byte| byte & 1 == 1)
}

#[cfg(test)]
mod tests;
