//! GOST 28147 key schedule and block transformation.

use crate::s_box::{BYTES as S_BOX_BYTES, COLUMNS, ROWS};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// Number of rounds.
const ROUNDS: usize = 32;
/// Number of 32-bit subkeys; the schedule is the key words, used cyclically.
pub(crate) const SUBKEYS: usize = KEY_BYTES / 4;

/// The order the subkeys are consumed in when encrypting: three passes forward,
/// then one backward.
#[rustfmt::skip]
const ENCRYPT_ORDER: [usize; ROUNDS] = [
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    7, 6, 5, 4, 3, 2, 1, 0,
];

/// The same schedule reversed, which is what inverts the Feistel network: one
/// pass forward, then three backward.
#[rustfmt::skip]
const DECRYPT_ORDER: [usize; ROUNDS] = [
    0, 1, 2, 3, 4, 5, 6, 7,
    7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0,
];

/// Splits the key into its little-endian subkeys.
///
/// GOST has no key expansion to speak of: the eight key words *are* the
/// schedule, and only the order they are used in changes.
pub(crate) fn expand_key(key: &[u8; KEY_BYTES]) -> [u32; SUBKEYS] {
    let mut subkeys = [0_u32; SUBKEYS];
    for (word, chunk) in subkeys.iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    subkeys
}

pub(crate) fn process_block(
    subkeys: &[u32; SUBKEYS],
    s_box: &[u8; S_BOX_BYTES],
    for_encryption: bool,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut n1 = u32::from_le_bytes(input[..4].try_into().unwrap());
    let mut n2 = u32::from_le_bytes(input[4..].try_into().unwrap());

    let order = if for_encryption {
        &ENCRYPT_ORDER
    } else {
        &DECRYPT_ORDER
    };

    let (last, rest) = order.split_last().expect("the schedule is never empty");
    for &subkey in rest {
        let previous = n1;
        n1 = n2 ^ main_step(n1, subkeys[subkey], s_box);
        n2 = previous;
    }
    // 最後一輪不交換兩半,這正是加解密能共用同一個迴圈的原因。
    n2 ^= main_step(n1, subkeys[*last], s_box);

    output[..4].copy_from_slice(&n1.to_le_bytes());
    output[4..].copy_from_slice(&n2.to_le_bytes());
}

/// Adds the subkey modulo `2^32`, substitutes each nibble, then rotates left by
/// eleven.
fn main_step(value: u32, subkey: u32, s_box: &[u8; S_BOX_BYTES]) -> u32 {
    let sum = value.wrapping_add(subkey);
    let mut substituted = 0_u32;
    for row in 0..ROWS {
        let nibble = ((sum >> (row * 4)) & 0xf) as usize;
        substituted |= u32::from(s_box[row * COLUMNS + nibble]) << (row * 4);
    }
    substituted.rotate_left(11)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s_box;

    #[test]
    fn the_decryption_schedule_is_the_encryption_schedule_reversed() {
        // Feistel 網路的反向就是把子鑰順序倒過來用。
        let mut reversed = ENCRYPT_ORDER;
        reversed.reverse();
        assert_eq!(reversed, DECRYPT_ORDER);
    }

    #[test]
    fn every_subkey_is_used_four_times() {
        for subkey in 0..SUBKEYS {
            for order in [ENCRYPT_ORDER, DECRYPT_ORDER] {
                assert_eq!(order.iter().filter(|&&used| used == subkey).count(), 4);
            }
        }
    }

    #[test]
    fn every_standard_table_round_trips() {
        let key = [0xa5_u8; KEY_BYTES];
        let subkeys = expand_key(&key);
        let plaintext = [0x3c_u8; BLOCK_BYTES];

        for table in [
            s_box::DEFAULT,
            s_box::E_TEST,
            s_box::E_A,
            s_box::E_B,
            s_box::E_C,
            s_box::E_D,
            s_box::D_A,
        ] {
            let mut ciphertext = [0_u8; BLOCK_BYTES];
            let mut recovered = [0_u8; BLOCK_BYTES];
            process_block(&subkeys, &table, true, &plaintext, &mut ciphertext);
            process_block(&subkeys, &table, false, &ciphertext, &mut recovered);
            assert_ne!(ciphertext, plaintext);
            assert_eq!(recovered, plaintext);
        }
    }

    #[test]
    fn different_tables_give_different_ciphertext() {
        let key = [0xa5_u8; KEY_BYTES];
        let subkeys = expand_key(&key);
        let plaintext = [0x3c_u8; BLOCK_BYTES];

        let mut with_default = [0_u8; BLOCK_BYTES];
        let mut with_e_a = [0_u8; BLOCK_BYTES];
        process_block(
            &subkeys,
            &s_box::DEFAULT,
            true,
            &plaintext,
            &mut with_default,
        );
        process_block(&subkeys, &s_box::E_A, true, &plaintext, &mut with_e_a);
        assert_ne!(with_default, with_e_a);
    }
}
