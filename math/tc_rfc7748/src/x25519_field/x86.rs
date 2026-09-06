//! X25519 欄位加減的 x86 SIMD 葉端。
//!
//! proof token 由呼叫端偵測一次取得；帶 `target_feature` 的函式不會在缺少
//! 對應指令集時被呼叫。最後兩個 limb 維持 scalar，避免為 10-limb 表示硬做
//! 額外 shuffle。

use super::{Fe, SIZE};
use tc_runtime::intrinsics::x86::{Avx2, Sse2};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(super) fn add_avx2(left: Fe, right: Fe, _proof: Avx2) -> Fe {
    // SAFETY: `proof` 證明目前 CPU 與作業系統可執行 AVX2。
    unsafe { add_avx2_inner(left, right) }
}

#[target_feature(enable = "avx2")]
unsafe fn add_avx2_inner(left: Fe, right: Fe) -> Fe {
    let left = left.raw_limbs();
    let right = right.raw_limbs();
    let mut output = [0_i32; SIZE];
    // SAFETY: 每次只讀寫陣列前八個 i32；unaligned intrinsics 不要求對齊。
    unsafe {
        let a = _mm256_loadu_si256(left.as_ptr().cast());
        let b = _mm256_loadu_si256(right.as_ptr().cast());
        _mm256_storeu_si256(output.as_mut_ptr().cast(), _mm256_add_epi32(a, b));
    }
    output[8] = left[8] + right[8];
    output[9] = left[9] + right[9];
    Fe(output)
}

pub(super) fn sub_avx2(left: Fe, right: Fe, _proof: Avx2) -> Fe {
    // SAFETY: `proof` 證明目前 CPU 與作業系統可執行 AVX2。
    unsafe { sub_avx2_inner(left, right) }
}

#[target_feature(enable = "avx2")]
unsafe fn sub_avx2_inner(left: Fe, right: Fe) -> Fe {
    let left = left.raw_limbs();
    let right = right.raw_limbs();
    let mut output = [0_i32; SIZE];
    // SAFETY: 每次只讀寫陣列前八個 i32；unaligned intrinsics 不要求對齊。
    unsafe {
        let a = _mm256_loadu_si256(left.as_ptr().cast());
        let b = _mm256_loadu_si256(right.as_ptr().cast());
        _mm256_storeu_si256(output.as_mut_ptr().cast(), _mm256_sub_epi32(a, b));
    }
    output[8] = left[8] - right[8];
    output[9] = left[9] - right[9];
    Fe(output)
}

pub(super) fn apm_avx2(left: Fe, right: Fe, _proof: Avx2) -> (Fe, Fe) {
    // SAFETY: `proof` 證明目前 CPU 與作業系統可執行 AVX2。
    unsafe { apm_avx2_inner(left, right) }
}

#[target_feature(enable = "avx2")]
unsafe fn apm_avx2_inner(left: Fe, right: Fe) -> (Fe, Fe) {
    let left = left.raw_limbs();
    let right = right.raw_limbs();
    let mut sum = [0_i32; SIZE];
    let mut difference = [0_i32; SIZE];
    // SAFETY: 每次只讀寫陣列前八個 i32；unaligned intrinsics 不要求對齊。
    unsafe {
        let a = _mm256_loadu_si256(left.as_ptr().cast());
        let b = _mm256_loadu_si256(right.as_ptr().cast());
        _mm256_storeu_si256(sum.as_mut_ptr().cast(), _mm256_add_epi32(a, b));
        _mm256_storeu_si256(difference.as_mut_ptr().cast(), _mm256_sub_epi32(a, b));
    }
    for index in 8..SIZE {
        sum[index] = left[index] + right[index];
        difference[index] = left[index] - right[index];
    }
    (Fe(sum), Fe(difference))
}

pub(super) fn add_sse2(left: Fe, right: Fe, _proof: Sse2) -> Fe {
    // SAFETY: `proof` 證明目前 CPU 可執行 SSE2。
    unsafe { add_sse2_inner(left, right) }
}

#[target_feature(enable = "sse2")]
unsafe fn add_sse2_inner(left: Fe, right: Fe) -> Fe {
    let left = left.raw_limbs();
    let right = right.raw_limbs();
    let mut output = [0_i32; SIZE];
    // SAFETY: 兩組 load/store 恰好涵蓋前八個 i32。
    unsafe {
        for offset in [0, 4] {
            let a = _mm_loadu_si128(left.as_ptr().add(offset).cast());
            let b = _mm_loadu_si128(right.as_ptr().add(offset).cast());
            _mm_storeu_si128(output.as_mut_ptr().add(offset).cast(), _mm_add_epi32(a, b));
        }
    }
    output[8] = left[8] + right[8];
    output[9] = left[9] + right[9];
    Fe(output)
}

pub(super) fn sub_sse2(left: Fe, right: Fe, _proof: Sse2) -> Fe {
    // SAFETY: `proof` 證明目前 CPU 可執行 SSE2。
    unsafe { sub_sse2_inner(left, right) }
}

#[target_feature(enable = "sse2")]
unsafe fn sub_sse2_inner(left: Fe, right: Fe) -> Fe {
    let left = left.raw_limbs();
    let right = right.raw_limbs();
    let mut output = [0_i32; SIZE];
    // SAFETY: 兩組 load/store 恰好涵蓋前八個 i32。
    unsafe {
        for offset in [0, 4] {
            let a = _mm_loadu_si128(left.as_ptr().add(offset).cast());
            let b = _mm_loadu_si128(right.as_ptr().add(offset).cast());
            _mm_storeu_si128(output.as_mut_ptr().add(offset).cast(), _mm_sub_epi32(a, b));
        }
    }
    output[8] = left[8] - right[8];
    output[9] = left[9] - right[9];
    Fe(output)
}

pub(super) fn apm_sse2(left: Fe, right: Fe, _proof: Sse2) -> (Fe, Fe) {
    // SAFETY: `proof` 證明目前 CPU 可執行 SSE2。
    unsafe { apm_sse2_inner(left, right) }
}

#[target_feature(enable = "sse2")]
unsafe fn apm_sse2_inner(left: Fe, right: Fe) -> (Fe, Fe) {
    let left = left.raw_limbs();
    let right = right.raw_limbs();
    let mut sum = [0_i32; SIZE];
    let mut difference = [0_i32; SIZE];
    // SAFETY: 兩組 load/store 恰好涵蓋前八個 i32。
    unsafe {
        for offset in [0, 4] {
            let a = _mm_loadu_si128(left.as_ptr().add(offset).cast());
            let b = _mm_loadu_si128(right.as_ptr().add(offset).cast());
            _mm_storeu_si128(sum.as_mut_ptr().add(offset).cast(), _mm_add_epi32(a, b));
            _mm_storeu_si128(
                difference.as_mut_ptr().add(offset).cast(),
                _mm_sub_epi32(a, b),
            );
        }
    }
    for index in 8..SIZE {
        sum[index] = left[index] + right[index];
        difference[index] = left[index] - right[index];
    }
    (Fe(sum), Fe(difference))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operands() -> (Fe, Fe) {
        (
            Fe(core::array::from_fn(|index| index as i32 * 17 - 61)),
            Fe(core::array::from_fn(|index| 91 - index as i32 * 13)),
        )
    }

    fn expected_add(left: Fe, right: Fe) -> Fe {
        let left = left.raw_limbs();
        let right = right.raw_limbs();
        Fe(core::array::from_fn(|index| left[index] + right[index]))
    }

    fn expected_sub(left: Fe, right: Fe) -> Fe {
        let left = left.raw_limbs();
        let right = right.raw_limbs();
        Fe(core::array::from_fn(|index| left[index] - right[index]))
    }

    fn assert_limbs_eq(left: Fe, right: Fe) {
        assert_eq!(left.raw_limbs(), right.raw_limbs());
    }

    #[test]
    fn available_backends_match_the_scalar_definition() {
        let (left, right) = operands();
        let expected_sum = expected_add(left, right);
        let expected_difference = expected_sub(left, right);
        let mut exercised = false;

        if let Some(proof) = Avx2::detect() {
            assert_limbs_eq(add_avx2(left, right, proof), expected_sum);
            assert_limbs_eq(sub_avx2(left, right, proof), expected_difference);
            let (sum, difference) = apm_avx2(left, right, proof);
            assert_limbs_eq(sum, expected_sum);
            assert_limbs_eq(difference, expected_difference);
            exercised = true;
        }
        if let Some(proof) = Sse2::detect() {
            assert_limbs_eq(add_sse2(left, right, proof), expected_sum);
            assert_limbs_eq(sub_sse2(left, right, proof), expected_difference);
            let (sum, difference) = apm_sse2(left, right, proof);
            assert_limbs_eq(sum, expected_sum);
            assert_limbs_eq(difference, expected_difference);
            exercised = true;
        }
        if !exercised {
            std::eprintln!("warning: X25519 SIMD test ran no AVX2/SSE2 backend");
        }
    }
}
