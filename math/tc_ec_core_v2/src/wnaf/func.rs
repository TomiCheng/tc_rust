use alloc::vec::Vec;
use crate::{Curve, Point, Scalar};

use super::{WNafTable, DEFAULT_WINDOW_SIZE_CUTOFFS, MAX_COMPACT_WIDTH, MAX_DENSE_WIDTH};

/// Joint sparse form of two unsigned scalars, least significant pair first.
/// Digits are in `-1..=1`. Carry bits avoid overflowing fixed-width scalars.
/// Variable time; suitable only for public scalars.
pub fn generate_jsf<C: Curve>(a: &C::Scalar, b: &C::Scalar) -> Vec<[i8; 2]> {
    let mut values = [a.clone(), b.clone()];
    let mut carry = [0_i32; 2];
    let mut result = Vec::new();
    while carry != [0, 0] || values.iter().any(|v| !v.is_zero()) {
        let n = [
            (values[0].low_bits(3) as i32 + carry[0]) & 7,
            (values[1].low_bits(3) as i32 + carry[1]) & 7,
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
            values[i] = values[i].shr(1);
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

    if scalar.is_zero() {
        return Vec::new();
    }

    // BC 以 carry 表示負 digit 帶來的進位，避免真的建立 `k + |digit|`。
    // 後者對全寬固定整數（例如 U256::MAX 的 NAF）會需要第 257 位。
    let mut value = scalar.clone();
    let mut digits = Vec::with_capacity(scalar.bit_length().saturating_add(1));
    let modulus = 1_i32 << width;
    let sign = modulus >> 1;
    let mut carry = false;
    let mut length = 0_usize;
    let mut position = 0_usize;

    while position <= value.bit_length() {
        if value.test_bit(position) == carry {
            position += 1;
            continue;
        }

        value = value.shr(position);
        let mut digit = value.low_bits(width) as i32;
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
    let bits = scalar.bit_length();
    assert!(bits < (1 << 16), "scalar bit length must be below 2^16");

    if scalar.is_zero() {
        return Vec::new();
    }

    let mut value = scalar.clone();
    let mut compact = Vec::with_capacity(bits / width + 1);
    let modulus = 1_i32 << width;
    let sign = modulus >> 1;
    let mut carry = false;
    let mut position = 0_usize;

    while position <= value.bit_length() {
        if value.test_bit(position) == carry {
            position += 1;
            continue;
        }

        value = value.shr(position);
        let mut digit = value.low_bits(width) as i32;
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

/// 使用顯式預算表執行 BC 形式的左到右 wNAF 乘法。
///
/// 此函式是變動時間實作，只能用於公開標量。
pub fn wnaf_mul<C: Curve>(table: &WNafTable<C::Point>, scalar: &C::Scalar) -> C::Point {
    let compact = generate_compact_window_naf::<C>(table.width(), scalar);
    let mut result = table.precomputed()[0].infinity();
    let mut index = compact.len();

    if index > 1 {
        index -= 1;
        let (digit, mut zeroes) = unpack(compact[index]);
        let absolute = digit.unsigned_abs() as usize;
        if (absolute << 2) < (1_usize << table.width()) {
            let highest = usize::BITS as usize - absolute.leading_zeros() as usize;
            let scale = table.width() - highest;
            let low_bits = absolute ^ (1_usize << (highest - 1));
            let first = (1_usize << (table.width() - 1)) - 1;
            let second = (low_bits << scale) + 1;
            let sign = digit.signum();
            result = table
                .select(sign * first as i32)
                .add(&table.select(sign * second as i32));
            zeroes -= scale;
        } else {
            result = table.select(digit);
        }
        result = result.times_pow2(zeroes);
    }

    while index > 0 {
        index -= 1;
        let (digit, zeroes) = unpack(compact[index]);
        result = result.twice_plus(&table.select(digit));
        result = result.times_pow2(zeroes);
    }
    result
}

/// 建立一次性預算表並執行 wNAF 乘法。
///
/// 重複乘同一個點時應改用 [`WNafTable`] 與 [`wnaf_mul`] 保存預算成本。
/// 此函式是變動時間實作，只能用於公開標量。
pub fn wnaf_mul_point<C: Curve>(point: &C::Point, scalar: &C::Scalar) -> C::Point {
    let width = get_window_size(scalar.bit_length());
    let table = WNafTable::new(point, width, true);
    wnaf_mul::<C>(&table, scalar)
}

fn unpack(compact: i32) -> (i32, usize) {
    (compact >> 16, (compact & 0xFFFF) as usize)
}