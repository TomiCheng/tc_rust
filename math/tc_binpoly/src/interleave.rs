//! 二進位多項式使用的位元交錯核心。
//!
//! 這組函式對應 Bouncy Castle `Math.Raw.Interleave`。平方會把每個輸入位元
//! 放到輸出的偶數位置；平方根快路徑則用反交錯把偶數位與奇數位拆開。
//! 函式本身不做多項式約簡，也不配置記憶體。

const M32: u64 = 0x5555_5555;
const M64: u64 = 0x5555_5555_5555_5555;
const M64_REVERSED: u64 = 0xAAAA_AAAA_AAAA_AAAA;

#[inline]
const fn bit_permute_step_u32(x: u32, mask: u32, shift: u32) -> u32 {
    let t = (x ^ (x >> shift)) & mask;
    t ^ (t << shift) ^ x
}

#[inline]
const fn bit_permute_step_u64(x: u64, mask: u64, shift: u32) -> u64 {
    let t = (x ^ (x >> shift)) & mask;
    t ^ (t << shift) ^ x
}

/// 將低 4 位展開到 8 位的偶數位置。
pub const fn expand4_to8(value: u8) -> u8 {
    let mut value = (value & 0x0F) as u32;
    value = (value | (value << 2)) & 0x33;
    value = (value | (value << 1)) & 0x55;
    value as u8
}

/// 將 8 位展開到 16 位的偶數位置。
pub const fn expand8_to16(value: u8) -> u16 {
    let mut value = value as u32;
    value = (value | (value << 4)) & 0x0F0F;
    value = (value | (value << 2)) & 0x3333;
    value = (value | (value << 1)) & 0x5555;
    value as u16
}

/// 將 16 位展開到 32 位的偶數位置。
pub const fn expand16_to32(value: u16) -> u32 {
    let mut value = value as u32;
    value = (value | (value << 8)) & 0x00FF_00FF;
    value = (value | (value << 4)) & 0x0F0F_0F0F;
    value = (value | (value << 2)) & 0x3333_3333;
    (value | (value << 1)) & 0x5555_5555
}

/// 將 32 位展開到 64 位的偶數位置。
pub const fn expand32_to64(mut value: u32) -> u64 {
    value = bit_permute_step_u32(value, 0x0000_FF00, 8);
    value = bit_permute_step_u32(value, 0x00F0_00F0, 4);
    value = bit_permute_step_u32(value, 0x0C0C_0C0C, 2);
    value = bit_permute_step_u32(value, 0x2222_2222, 1);
    (((value >> 1) as u64 & M32) << 32) | (value as u64 & M32)
}

/// 將一個 64 位字展開為 128 位平方表示，低字在前。
pub const fn expand64_to128(mut value: u64) -> [u64; 2] {
    value = bit_permute_step_u64(value, 0x0000_0000_FFFF_0000, 16);
    value = bit_permute_step_u64(value, 0x0000_FF00_0000_FF00, 8);
    value = bit_permute_step_u64(value, 0x00F0_00F0_00F0_00F0, 4);
    value = bit_permute_step_u64(value, 0x0C0C_0C0C_0C0C_0C0C, 2);
    value = bit_permute_step_u64(value, 0x2222_2222_2222_2222, 1);
    [value & M64, (value >> 1) & M64]
}

/// 將輸入 slice 逐字展開到兩倍長度的輸出 slice。
///
/// 輸入與輸出不可重疊；輸出長度必須恰為輸入的兩倍。
pub fn expand64_to128_into(input: &[u64], output: &mut [u64]) {
    assert_eq!(
        output.len(),
        input.len() * 2,
        "expanded output length differs"
    );
    let (pairs, remainder) = output.as_chunks_mut::<2>();
    debug_assert!(remainder.is_empty());
    for (&value, pair) in input.iter().zip(pairs) {
        *pair = expand64_to128(value);
    }
}

/// 將一個 64 位字反向展開到 128 位的奇數位置，低字在前。
pub const fn expand64_to128_rev(mut value: u64) -> [u64; 2] {
    value = bit_permute_step_u64(value, 0x0000_0000_FFFF_0000, 16);
    value = bit_permute_step_u64(value, 0x0000_FF00_0000_FF00, 8);
    value = bit_permute_step_u64(value, 0x00F0_00F0_00F0_00F0, 4);
    value = bit_permute_step_u64(value, 0x0C0C_0C0C_0C0C_0C0C, 2);
    value = bit_permute_step_u64(value, 0x2222_2222_2222_2222, 1);
    [value & M64_REVERSED, (value << 1) & M64_REVERSED]
}

/// 把低半部交錯到偶數位、高半部交錯到奇數位。
pub const fn shuffle_u32(mut value: u32) -> u32 {
    value = bit_permute_step_u32(value, 0x0000_FF00, 8);
    value = bit_permute_step_u32(value, 0x00F0_00F0, 4);
    value = bit_permute_step_u32(value, 0x0C0C_0C0C, 2);
    bit_permute_step_u32(value, 0x2222_2222, 1)
}

/// 把低半部交錯到偶數位、高半部交錯到奇數位。
pub const fn shuffle_u64(mut value: u64) -> u64 {
    value = bit_permute_step_u64(value, 0x0000_0000_FFFF_0000, 16);
    value = bit_permute_step_u64(value, 0x0000_FF00_0000_FF00, 8);
    value = bit_permute_step_u64(value, 0x00F0_00F0_00F0_00F0, 4);
    value = bit_permute_step_u64(value, 0x0C0C_0C0C_0C0C_0C0C, 2);
    bit_permute_step_u64(value, 0x2222_2222_2222_2222, 1)
}

/// 把四個等寬區段交錯到每四位中的相同位置。
pub const fn shuffle2_u32(mut value: u32) -> u32 {
    value = bit_permute_step_u32(value, 0x0000_F0F0, 12);
    value = bit_permute_step_u32(value, 0x00CC_00CC, 6);
    value = bit_permute_step_u32(value, 0x2222_2222, 1);
    bit_permute_step_u32(value, 0x0C0C_0C0C, 2)
}

/// 把四個等寬區段交錯到每四位中的相同位置。
pub const fn shuffle2_u64(mut value: u64) -> u64 {
    value = bit_permute_step_u64(value, 0x0000_0000_FF00_FF00, 24);
    value = bit_permute_step_u64(value, 0x0000_F0F0_0000_F0F0, 12);
    value = bit_permute_step_u64(value, 0x00CC_00CC_00CC_00CC, 6);
    bit_permute_step_u64(value, 0x0A0A_0A0A_0A0A_0A0A, 3)
}

/// 將偶數位收進低半部、奇數位收進高半部。
pub const fn unshuffle_u32(mut value: u32) -> u32 {
    value = bit_permute_step_u32(value, 0x2222_2222, 1);
    value = bit_permute_step_u32(value, 0x0C0C_0C0C, 2);
    value = bit_permute_step_u32(value, 0x00F0_00F0, 4);
    bit_permute_step_u32(value, 0x0000_FF00, 8)
}

/// 將偶數位收進低半部、奇數位收進高半部。
pub const fn unshuffle_u64(mut value: u64) -> u64 {
    value = bit_permute_step_u64(value, 0x2222_2222_2222_2222, 1);
    value = bit_permute_step_u64(value, 0x0C0C_0C0C_0C0C_0C0C, 2);
    value = bit_permute_step_u64(value, 0x00F0_00F0_00F0_00F0, 4);
    value = bit_permute_step_u64(value, 0x0000_FF00_0000_FF00, 8);
    bit_permute_step_u64(value, 0x0000_0000_FFFF_0000, 16)
}

/// 將一個字拆成偶數位與奇數位；回傳 `(even, odd)`。
pub const fn unshuffle_to_even_odd(value: u64) -> (u64, u64) {
    let value = unshuffle_u64(value);
    (value & 0xFFFF_FFFF, value >> 32)
}

/// 將相鄰兩個字拆成連續的偶數位與奇數位；回傳 `(even, odd)`。
pub const fn unshuffle_pair_to_even_odd(low: u64, high: u64) -> (u64, u64) {
    let low = unshuffle_u64(low);
    let high = unshuffle_u64(high);
    (
        (high << 32) | (low & 0xFFFF_FFFF),
        (low >> 32) | (high & 0xFFFF_FFFF_0000_0000),
    )
}

/// [`shuffle2_u32`] 的反排列。
pub const fn unshuffle2_u32(mut value: u32) -> u32 {
    value = bit_permute_step_u32(value, 0x0C0C_0C0C, 2);
    value = bit_permute_step_u32(value, 0x2222_2222, 1);
    value = bit_permute_step_u32(value, 0x0000_F0F0, 12);
    bit_permute_step_u32(value, 0x00CC_00CC, 6)
}

/// [`shuffle2_u64`] 的反排列。
pub const fn unshuffle2_u64(mut value: u64) -> u64 {
    value = bit_permute_step_u64(value, 0x00CC_00CC_00CC_00CC, 6);
    value = bit_permute_step_u64(value, 0x0A0A_0A0A_0A0A_0A0A, 3);
    value = bit_permute_step_u64(value, 0x0000_0000_FF00_FF00, 24);
    bit_permute_step_u64(value, 0x0000_F0F0_0000_F0F0, 12)
}

/// 將 8 x 8 位元矩陣轉置。
pub const fn transpose(mut value: u64) -> u64 {
    value = bit_permute_step_u64(value, 0x0000_0000_F0F0_F0F0, 28);
    value = bit_permute_step_u64(value, 0x0000_CCCC_0000_CCCC, 14);
    bit_permute_step_u64(value, 0x00AA_00AA_00AA_00AA, 7)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_expand(value: u64, bits: usize, offset: usize) -> u128 {
        let mut result = 0_u128;
        for bit in 0..bits {
            if value & (1_u64 << bit) != 0 {
                result |= 1_u128 << (bit * 2 + offset);
            }
        }
        result
    }

    fn reference_expand_rev(value: u64) -> u128 {
        let mut result = 0_u128;
        for bit in 0..64 {
            if value & (1_u64 << bit) != 0 {
                let half = if bit < 32 { 1 } else { 0 };
                result |= 1_u128 << (half * 64 + (bit & 31) * 2 + 1);
            }
        }
        result
    }

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn every_expand_width_matches_independent_bit_placement() {
        for value in 0_u64..=u16::MAX as u64 {
            if value <= 0x0F {
                assert_eq!(
                    expand4_to8(value as u8) as u128,
                    reference_expand(value, 4, 0)
                );
            }
            if value <= 0xFF {
                assert_eq!(
                    expand8_to16(value as u8) as u128,
                    reference_expand(value, 8, 0)
                );
            }
            assert_eq!(
                expand16_to32(value as u16) as u128,
                reference_expand(value, 16, 0)
            );
        }

        let mut seed = 0x1EAF_5EED_7748_2551;
        for _ in 0..512 {
            let value = next(&mut seed);
            assert_eq!(
                expand32_to64(value as u32) as u128,
                reference_expand(value, 32, 0)
            );
            let expanded = expand64_to128(value);
            assert_eq!(
                expanded[0] as u128 | ((expanded[1] as u128) << 64),
                reference_expand(value, 64, 0)
            );
            let reversed = expand64_to128_rev(value);
            assert_eq!(
                reversed[0] as u128 | ((reversed[1] as u128) << 64),
                reference_expand_rev(value)
            );
        }
    }

    #[test]
    fn slice_expansion_and_even_odd_split_match_bit_reference() {
        let input = [0, 1, u64::MAX, 0x0123_4567_89AB_CDEF];
        let mut output = [0_u64; 8];
        expand64_to128_into(&input, &mut output);
        let (pairs, remainder) = output.as_chunks::<2>();
        assert!(remainder.is_empty());
        for (value, pair) in input.into_iter().zip(pairs) {
            assert_eq!(*pair, expand64_to128(value));
            let (even, odd) = unshuffle_pair_to_even_odd(pair[0], pair[1]);
            assert_eq!(even, value);
            assert_eq!(odd, 0);
        }
    }

    #[test]
    fn shuffle_families_are_exact_inverses() {
        let mut seed = 0x5A11_F1E2_D00D_CAFE;
        for _ in 0..512 {
            let value = next(&mut seed);
            assert_eq!(unshuffle_u32(shuffle_u32(value as u32)), value as u32);
            assert_eq!(unshuffle_u64(shuffle_u64(value)), value);
            assert_eq!(unshuffle2_u32(shuffle2_u32(value as u32)), value as u32);
            assert_eq!(unshuffle2_u64(shuffle2_u64(value)), value);

            let shuffled = shuffle_u64(value);
            let (even, odd) = unshuffle_to_even_odd(shuffled);
            assert_eq!(even, value & 0xFFFF_FFFF);
            assert_eq!(odd, value >> 32);
        }
    }

    #[test]
    fn transpose_matches_independent_matrix_mapping_and_is_an_involution() {
        let mut seed = 0x7A4A_5EED_0123_4567;
        for _ in 0..512 {
            let value = next(&mut seed);
            let mut expected = 0_u64;
            for row in 0..8 {
                for column in 0..8 {
                    let source = row * 8 + column;
                    let destination = column * 8 + row;
                    expected |= ((value >> source) & 1) << destination;
                }
            }
            assert_eq!(transpose(value), expected);
            assert_eq!(transpose(transpose(value)), value);
        }
    }
}
