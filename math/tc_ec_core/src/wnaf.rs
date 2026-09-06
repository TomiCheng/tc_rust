//! 公開標量使用的 window non-adjacent form 與左到右乘法器。
//!
//! wNAF 的 digit 分布、分支與預算表索引都依賴標量，因此本模組是變動時間
//! 實作，只適合公開標量。預算表由呼叫端顯式持有，不藏進點內，也不需要鎖或
//! 內部可變性。

use alloc::vec::Vec;

use crate::{Curve, Point};

const DEFAULT_WINDOW_SIZE_CUTOFFS: [usize; 6] = [13, 41, 121, 337, 897, 2305];
const MAX_DENSE_WIDTH: usize = 8;
const MAX_COMPACT_WIDTH: usize = 16;

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

        value = scalar_shr::<C>(&value, position);
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

        value = scalar_shr::<C>(&value, position);
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

/// 呼叫端持有的 wNAF 奇數倍點預算表。
#[derive(Clone, Debug)]
pub struct WNafTable<P> {
    width: usize,
    precomputed: Vec<P>,
    precomputed_negated: Option<Vec<P>>,
}

impl<P: Point> WNafTable<P> {
    /// 建立 `P, 3P, 5P, ...`，並可選擇一併保存其負值。
    pub fn new(point: &P, width: usize, include_negated: bool) -> Self {
        assert!(
            (2..=MAX_COMPACT_WIDTH).contains(&width),
            "wNAF table width must be in the range 2..=16"
        );
        let count = 1_usize << (width - 2);
        let twice = point.double();
        let mut precomputed = Vec::with_capacity(count);
        let mut current = point.clone();
        precomputed.push(current.clone());
        for _ in 1..count {
            current = current.add(&twice);
            precomputed.push(current.clone());
        }
        let precomputed_negated =
            include_negated.then(|| precomputed.iter().map(Point::negate).collect::<Vec<_>>());
        Self {
            width,
            precomputed,
            precomputed_negated,
        }
    }

    /// 預算表的窗寬。
    pub const fn width(&self) -> usize {
        self.width
    }

    /// 正奇數倍點 `P, 3P, 5P, ...`。
    pub fn precomputed(&self) -> &[P] {
        &self.precomputed
    }

    /// 預先保存的負奇數倍點；未要求時為 `None`。
    pub fn precomputed_negated(&self) -> Option<&[P]> {
        self.precomputed_negated.as_deref()
    }

    fn select(&self, digit: i32) -> P {
        let index = digit.unsigned_abs() as usize >> 1;
        if digit < 0 {
            self.precomputed_negated.as_ref().map_or_else(
                || self.precomputed[index].negate(),
                |points| points[index].clone(),
            )
        } else {
            self.precomputed[index].clone()
        }
    }
}

/// 使用顯式預算表執行 BC 形式的左到右 wNAF 乘法。
///
/// 此函式是變動時間實作，只能用於公開標量。
pub fn wnaf_mul<C: Curve>(table: &WNafTable<C::Point>, scalar: &C::Scalar) -> C::Point {
    let compact = generate_compact_window_naf::<C>(table.width, scalar);
    let mut result = table.precomputed[0].identity();
    let mut index = compact.len();

    if index > 1 {
        index -= 1;
        let (digit, mut zeroes) = unpack(compact[index]);
        let absolute = digit.unsigned_abs() as usize;
        if (absolute << 2) < (1_usize << table.width) {
            let highest = usize::BITS as usize - absolute.leading_zeros() as usize;
            let scale = table.width - highest;
            let low_bits = absolute ^ (1_usize << (highest - 1));
            let first = (1_usize << (table.width - 1)) - 1;
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
    let width = get_window_size(C::scalar_bit_length(scalar));
    let table = WNafTable::new(point, width, true);
    wnaf_mul::<C>(&table, scalar)
}

fn scalar_shr<C: Curve>(scalar: &C::Scalar, count: usize) -> C::Scalar {
    let mut shifted = scalar.clone();
    for _ in 0..count {
        shifted = C::scalar_shr1(&shifted);
    }
    shifted
}

fn unpack(compact: i32) -> (i32, usize) {
    (compact >> 16, (compact & 0xFFFF) as usize)
}
