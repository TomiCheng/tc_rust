//! IDEA key schedule and block transformation.

use crate::{BLOCK_BYTES, KEY_BYTES};

/// Modulus of the multiplication group, `2^16 + 1`.
const BASE: u32 = 0x1_0001;
/// Sixteen-bit mask; every intermediate value is reduced to a 16-bit word.
const MASK: u32 = 0xffff;
/// Subkey words per round: four for the input transform, two for the MA box.
const ROUND_WORDS: usize = 6;
/// Number of rounds.
const ROUNDS: usize = 8;
/// Total subkey words: eight rounds of six, plus four for the output transform.
pub(crate) const SUBKEY_WORDS: usize = ROUNDS * ROUND_WORDS + 4;

/// Expands `key` into the direction-specific subkey schedule.
pub(crate) fn generate_working_key(
    for_encryption: bool,
    key: &[u8; KEY_BYTES],
) -> [u16; SUBKEY_WORDS] {
    let expanded = expand_key(key);
    if for_encryption {
        expanded
    } else {
        invert_key(&expanded)
    }
}

/// Transforms one block with `working_key`, which already encodes the direction.
pub(crate) fn process_block(
    working_key: &[u16; SUBKEY_WORDS],
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut x0 = u32::from(u16::from_be_bytes([input[0], input[1]]));
    let mut x1 = u32::from(u16::from_be_bytes([input[2], input[3]]));
    let mut x2 = u32::from(u16::from_be_bytes([input[4], input[5]]));
    let mut x3 = u32::from(u16::from_be_bytes([input[6], input[7]]));

    let (rounds, output_transform) = working_key.split_at(ROUNDS * ROUND_WORDS);
    for round in rounds.chunks_exact(ROUND_WORDS) {
        x0 = mul(x0, u32::from(round[0]));
        x1 = (x1 + u32::from(round[1])) & MASK;
        x2 = (x2 + u32::from(round[2])) & MASK;
        x3 = mul(x3, u32::from(round[3]));

        let t0 = x1;
        let t1 = x2;
        x2 ^= x0;
        x1 ^= x3;
        x2 = mul(x2, u32::from(round[4]));
        x1 = (x1 + x2) & MASK;
        x1 = mul(x1, u32::from(round[5]));
        x2 = (x2 + x1) & MASK;
        x0 ^= x1;
        x3 ^= x2;
        x1 ^= t1;
        x2 ^= t0;
    }

    // 輸出轉換取消最後一輪的 x1/x2 交換,故此處讀 x2 再讀 x1。
    let o0 = mul(x0, u32::from(output_transform[0])) as u16;
    let o1 = ((x2 + u32::from(output_transform[1])) & MASK) as u16;
    let o2 = ((x1 + u32::from(output_transform[2])) & MASK) as u16;
    let o3 = mul(x3, u32::from(output_transform[3])) as u16;

    output[0..2].copy_from_slice(&o0.to_be_bytes());
    output[2..4].copy_from_slice(&o1.to_be_bytes());
    output[4..6].copy_from_slice(&o2.to_be_bytes());
    output[6..8].copy_from_slice(&o3.to_be_bytes());
}

/// Multiplication modulo `2^16 + 1`, where a zero word represents `2^16`.
fn mul(x: u32, y: u32) -> u32 {
    if x == 0 {
        (BASE - y) & MASK
    } else if y == 0 {
        (BASE - x) & MASK
    } else {
        // 兩個運算元皆 <= 0xffff,乘積不會溢位 u32。
        let product = x * y;
        let low = product & MASK;
        let high = product >> 16;
        (low.wrapping_sub(high).wrapping_add(u32::from(low < high))) & MASK
    }
}

/// Multiplicative inverse modulo `2^16 + 1` by the extended Euclidean
/// algorithm; zero and one are their own inverses.
fn mul_inv(x: u32) -> u32 {
    if x < 2 {
        return x;
    }

    let mut x = x;
    let mut t0: u32 = 1;
    let mut t1 = BASE / x;
    let mut y = BASE % x;
    while y != 1 {
        let quotient = x / y;
        x %= y;
        // 累加項可能超過 16 位元,先環繞相加再遮罩,與 bc 的 32 位元行為一致。
        t0 = t0.wrapping_add(t1.wrapping_mul(quotient)) & MASK;
        if x == 1 {
            return t0;
        }
        let quotient = y / x;
        y %= x;
        t1 = t1.wrapping_add(t0.wrapping_mul(quotient)) & MASK;
    }
    1_u32.wrapping_sub(t1) & MASK
}

/// Additive inverse modulo `2^16`.
fn add_inv(x: u32) -> u32 {
    x.wrapping_neg() & MASK
}

/// Expands the 128-bit key into the encryption schedule: the first eight words
/// are taken verbatim, then each further block of eight is the previous block
/// rotated left by 25 bits.
fn expand_key(key: &[u8; KEY_BYTES]) -> [u16; SUBKEY_WORDS] {
    let mut schedule = [0_u16; SUBKEY_WORDS];
    for (word, bytes) in schedule.iter_mut().zip(key.chunks_exact(2)) {
        *word = u16::from_be_bytes([bytes[0], bytes[1]]);
    }
    for index in 8..SUBKEY_WORDS {
        // 每項都落在 16 位元內,u16 運算等同 bc 的 `& Mask`。
        schedule[index] = match index & 7 {
            0..=5 => (schedule[index - 7] & 127) << 9 | schedule[index - 6] >> 7,
            6 => (schedule[index - 7] & 127) << 9 | schedule[index - 14] >> 7,
            _ => (schedule[index - 15] & 127) << 9 | schedule[index - 14] >> 7,
        };
    }
    schedule
}

/// Derives the decryption schedule from the encryption schedule by replacing
/// each subkey with its multiplicative or additive inverse and reversing the
/// round order.
fn invert_key(encryption_key: &[u16; SUBKEY_WORDS]) -> [u16; SUBKEY_WORDS] {
    let mut schedule = [0_u16; SUBKEY_WORDS];
    let mut read = 0;
    let mut write = SUBKEY_WORDS;

    // 讀取游標由前往後,寫入游標由後往前,所以每組都是反序寫入。輸入轉換的四個
    // 子鑰共九組,兩兩之間夾著 MA 盒的兩個子鑰。
    for group in 0..=ROUNDS {
        let inverted = [
            mul_inv(u32::from(encryption_key[read])),
            add_inv(u32::from(encryption_key[read + 1])),
            add_inv(u32::from(encryption_key[read + 2])),
            mul_inv(u32::from(encryption_key[read + 3])),
        ];
        read += 4;

        // 首尾兩組直接反轉;中間各組的兩個加法反元素還要再對調一次,因為解密時
        // MA 盒的輸出分支順序與加密相反。
        let swap_middle = group != 0 && group != ROUNDS;
        for value in [
            inverted[3],
            if swap_middle {
                inverted[1]
            } else {
                inverted[2]
            },
            if swap_middle {
                inverted[2]
            } else {
                inverted[1]
            },
            inverted[0],
        ] {
            write -= 1;
            schedule[write] = value as u16;
        }

        if group == ROUNDS {
            break;
        }

        // MA 盒的兩個子鑰不取反元素,原樣搬移。
        for offset in [1, 0] {
            write -= 1;
            schedule[write] = encryption_key[read + offset];
        }
        read += 2;
    }

    debug_assert_eq!(read, SUBKEY_WORDS);
    debug_assert_eq!(write, 0);
    schedule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_operand_stands_for_two_to_the_sixteen() {
        // 0 代表 2^16:2^16 * 1 = 2^16,仍以 0 表示。
        assert_eq!(mul(0, 1), 0);
        // 2^16 * 2^16 = 2^32 ≡ 1 (mod 65537)。
        assert_eq!(mul(0, 0), 1);
    }

    #[test]
    fn every_word_has_a_multiplicative_inverse() {
        // 含 x = 0,因為它代表 2^16,而 2^32 ≡ 1 (mod 65537),故自身即為反元素。
        for x in 0..=MASK {
            assert_eq!(mul(x, mul_inv(x)), 1, "x = {x}");
        }
    }

    #[test]
    fn additive_inverses_cancel() {
        for x in [0, 1, 2, 12345, MASK] {
            assert_eq!((x + add_inv(x)) & MASK, 0);
        }
    }

    #[test]
    fn the_decryption_schedule_undoes_the_encryption_schedule() {
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let encryption_key = generate_working_key(true, &key);
        let decryption_key = generate_working_key(false, &key);

        let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut ciphertext = [0_u8; BLOCK_BYTES];
        let mut recovered = [0_u8; BLOCK_BYTES];
        process_block(&encryption_key, &plaintext, &mut ciphertext);
        process_block(&decryption_key, &ciphertext, &mut recovered);

        assert_ne!(ciphertext, plaintext);
        assert_eq!(recovered, plaintext);
    }
}
