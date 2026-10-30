use tc_bigint::{BigUint, Limb, Word};

/// BC `WNafUtilities.GetNafWeight`：k 的 NAF 中非零位數的個數，也就是 3k XOR k 的 1 位元
/// 數，逐 limb 帶進位計算，不需要更寬的整數。常數時間：每個 limb 都走過。
pub(crate) fn naf_weight(limbs: &[Limb]) -> u32 {
    let (mut top, mut carry, mut weight): (Word, Word, u32) = (0, 0, 0);
    for limb in limbs {
        let x = limb.to_word();
        let doubled = (x << 1) | top;
        top = x >> (Word::BITS - 1);
        let (sum, low) = doubled.overflowing_add(x);
        let (sum, high) = sum.overflowing_add(carry);
        carry = Word::from(low) + Word::from(high);
        weight += (sum ^ x).count_ones();
    }
    // limb 之後 k 是 0，3k 只剩進位出來的部分。
    weight + (top + carry).count_ones()
}

/// 由高位往低位逐 limb 求 `value mod modulus`。變動時間：只用於公開值。
pub(crate) fn rem_u32(value: &BigUint, modulus: u32) -> u32 {
    let modulus = u128::from(modulus);
    let mut r = 0u128;
    for limb in value.as_limbs().iter().rev() {
        r = ((r << Word::BITS) | u128::from(limb.to_word())) % modulus;
    }
    r as u32
}

/// BC `DHPublicKeyParameters.Legendre`：奇數 b 的 Jacobi 符號 (a / b)，以 1、−1 或 0 表示；
/// b 是質數時就是 Legendre 符號。照 BC 的二進位減法版本，a 必須小於 b。變動時間：只用於
/// 公開值。
pub(crate) fn legendre(a: &BigUint, b: &BigUint) -> i32 {
    let low = |v: &BigUint| v.as_limbs().first().map_or(0, |limb| limb.to_word() as u32);
    let (mut a, mut b) = (a.clone(), b.clone());
    let mut r = 0u32;
    loop {
        let Some(shift) = a.trailing_zeros() else {
            // a 是 0：b 大於 1 時不互質。
            return 0;
        };
        if shift > 0 {
            a >>= shift;
            let bits = low(&b);
            r ^= (bits ^ (bits >> 1)) & (shift << 1);
        }
        if a == b {
            break;
        }
        if a < b {
            r ^= low(&a) & low(&b);
            core::mem::swap(&mut a, &mut b);
        }
        a -= &b;
    }
    if b == BigUint::from(1u8) {
        1 - (r & 2) as i32
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{legendre, naf_weight, rem_u32};
    use tc_bigint::BigUint;

    // 以定義算 Jacobi 符號：(a / p) ≡ a^((p - 1) / 2) mod p，p 為奇質數。
    fn euler(a: u64, p: u64) -> i32 {
        let mut result = 1u128;
        let (mut base, mut exponent) = (u128::from(a % p), (p - 1) / 2);
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * base % u128::from(p);
            }
            base = base * base % u128::from(p);
            exponent >>= 1;
        }
        match result {
            0 => 0,
            1 => 1,
            _ => -1,
        }
    }

    #[test]
    fn the_legendre_symbol_matches_euler_s_criterion() {
        for p in [3u64, 5, 7, 11, 13, 23, 47, 1_000_003, 2_147_483_647] {
            for a in 1..p.min(200) {
                assert_eq!(
                    legendre(&BigUint::from(a), &BigUint::from(p)),
                    euler(a, p),
                    "({a} / {p})"
                );
            }
        }
    }

    #[test]
    fn the_naf_weight_counts_the_nonzero_digits() {
        // 7 = 8 − 1 的 NAF 有兩個非零位數；0b101_0101 本身就是 NAF，有四個。
        for (value, weight) in [
            (0u64, 0),
            (1, 1),
            (3, 2),
            (7, 2),
            (0b101_0101, 4),
            (u64::MAX, 2),
        ] {
            assert_eq!(
                naf_weight(BigUint::from(value).as_limbs()),
                weight,
                "{value}"
            );
        }
    }

    #[test]
    fn the_remainder_by_a_small_modulus_matches_u128_arithmetic() {
        let value = u128::MAX - 12_345;
        for modulus in [3u32, 7, 223_092_870, u32::MAX] {
            assert_eq!(
                rem_u32(&BigUint::from(value), modulus),
                (value % u128::from(modulus)) as u32
            );
        }
    }
}
