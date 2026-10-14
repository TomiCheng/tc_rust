use alloc::vec::Vec;
use crate::Curve;

use super::{DEFAULT_WINDOW_SIZE_CUTOFFS, MAX_COMPACT_WIDTH, MAX_DENSE_WIDTH};

/// Joint sparse form of two unsigned scalars, least significant pair first.
/// Digits are in `-1..=1`. Carry bits avoid overflowing fixed-width scalars.
/// Variable time; suitable only for public scalars.
pub fn generate_jsf<C: Curve>(a: &C::Scalar, b: &C::Scalar) -> Vec<[i8; 2]> {
    let mut values = [a.clone(), b.clone()];
    let mut carry = [0_i32; 2];
    let mut result = Vec::new();
    while carry != [0, 0] || values.iter().any(|v| !C::scalar_is_zero(v)) {
        let n = [
            (C::scalar_low_bits(&values[0], 3) as i32 + carry[0]) & 7,
            (C::scalar_low_bits(&values[1], 3) as i32 + carry[1]) & 7,
        ];
        let mut digit = [0_i8; 2];
        for i in 0..2 {
            let mut u = n[i] & 1;
            if u != 0 {
                u -= n[i] & 2;
                if n[i] + u == 4 && n[1 - i] & 3 == 2 {
                    u = -u;
                }
            }
            if carry[i] * 2 == 1 + u {
                carry[i] ^= 1;
            }
            digit[i] = u as i8;
            values[i] = C::scalar_shr1(&values[i]);
        }
        result.push(digit);
    }
    result
}

// 刻意不在 `Curve` 加 `MAX_SCALAR_BITS`：BigUint 後端本來就無上限，填固定值
// 會製造假的契約；改成 `Option` 也無法在 stable Rust 將泛型 associated const
// 直接用作陣列長度。況且 `WNafTable` 自身仍以 Vec 保存預算點。若未來需要
// 完整 no-alloc wNAF，應另設 caller-provided scratch／固定表 API，而不是讓所有
// Curve 實作背負一個目前無法兌現的最大位元數。

/// 產生只含 `-1`、`0`、`1` 的 NAF，最低位 digit 位於 index 0。
///
/// 此函式是變動時間實作，只能用於公開標量。
pub fn generate_naf<C: Curve>(scalar: &C::Scalar) -> Vec<i8> {
    generate_window_naf::<C>(2, scalar)
}

/// 產生指定寬度的 wNAF，最低位 digit 位於 index 0。
///
/// `width` 必須在 2 到 8；非零 digit 必為奇數，且絕對值小於
/// `2^(width - 1)`。此函式是變動時間實作，只能用於公開標量。
pub fn generate_window_naf<C: Curve>(width: usize, scalar: &C::Scalar) -> Vec<i8> {
    assert!(
        (2..=MAX_DENSE_WIDTH).contains(&width),
        "wNAF width must be in the range 2..=8"
    );

    if C::scalar_is_zero(scalar) {
        return Vec::new();
    }

    // BC 以 carry 表示負 digit 帶來的進位，避免真的建立 `k + |digit|`。
    // 後者對全寬固定整數（例如 U256::MAX 的 NAF）會需要第 257 位。
    let mut value = scalar.clone();
    let mut digits = Vec::with_capacity(C::scalar_bit_length(scalar).saturating_add(1));
    let modulus = 1_i32 << width;
    let sign = modulus >> 1;
    let mut carry = false;
    let mut length = 0_usize;
    let mut position = 0_usize;

    while position <= C::scalar_bit_length(&value) {
        if C::scalar_test_bit(&value, position) == carry {
            position += 1;
            continue;
        }

        value = C::scalar_shr(&value, position);
        let mut digit = C::scalar_low_bits(&value, width) as i32;
        if carry {
            digit += 1;
        }
        carry = digit & sign != 0;
        if carry {
            digit -= modulus;
        }

        length += if length == 0 { position } else { position - 1 };
        digits.resize(length, 0);
        digits.push(digit as i8);
        length += 1;
        position = width;
    }
    digits
}

/// 產生 BC `WNafL2RMultiplier` 使用的緊湊 wNAF。
///
/// 每個 `i32` 的高 16 位是有號 digit，低 16 位是前一個非零 digit 之後的
/// 連續零數。`width` 必須在 2 到 16，標量位元長必須小於 `2^16`。
/// 此函式是變動時間實作，只能用於公開標量。
pub fn generate_compact_window_naf<C: Curve>(width: usize, scalar: &C::Scalar) -> Vec<i32> {
    assert!(
        (2..=MAX_COMPACT_WIDTH).contains(&width),
        "compact wNAF width must be in the range 2..=16"
    );
    let bits = C::scalar_bit_length(scalar);
    assert!(bits < (1 << 16), "scalar bit length must be below 2^16");

    if C::scalar_is_zero(scalar) {
        return Vec::new();
    }

    let mut value = scalar.clone();
    let mut compact = Vec::with_capacity(bits / width + 1);
    let modulus = 1_i32 << width;
    let sign = modulus >> 1;
    let mut carry = false;
    let mut position = 0_usize;

    while position <= C::scalar_bit_length(&value) {
        if C::scalar_test_bit(&value, position) == carry {
            position += 1;
            continue;
        }

        value = C::scalar_shr(&value, position);
        let mut digit = C::scalar_low_bits(&value, width) as i32;
        if carry {
            digit += 1;
        }
        carry = digit & sign != 0;
        if carry {
            digit -= modulus;
        }

        let zeroes = if compact.is_empty() {
            position
        } else {
            position - 1
        };
        compact.push((digit << 16) | zeroes as i32);
        position = width;
    }
    compact
}

/// 依 BC 的門檻表選擇預設窗寬。
pub fn get_window_size(bits: usize) -> usize {
    let mut width = 0;
    while width < DEFAULT_WINDOW_SIZE_CUTOFFS.len() && bits >= DEFAULT_WINDOW_SIZE_CUTOFFS[width] {
        width += 1;
    }
    (width + 2).clamp(2, MAX_COMPACT_WIDTH)
}

/// 回傳標量 NAF 中的非零 digit 數。
///
/// 此函式是變動時間實作，只能用於公開標量。
pub fn get_naf_weight<C: Curve>(scalar: &C::Scalar) -> usize {
    generate_naf::<C>(scalar)
        .into_iter()
        .filter(|digit| *digit != 0)
        .count()
}