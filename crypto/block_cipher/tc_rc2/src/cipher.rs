//! RC2 key schedule and block transforms.
//!
//! The round math mirrors Bouncy Castle's signed-integer implementation.
//! Values are reduced to sixteen bits by each rotation and when written out.

/// Expanded RC2 key length in 16-bit words.
pub(crate) const SUBKEYS: usize = 64;

/// Key-expansion table based on the digits of pi (RFC 2268).
#[rustfmt::skip]
const PI_TABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

/// Expands a key to the sixty-four working words defined by RFC 2268.
pub(crate) fn expand_key(key: &[u8], effective_key_bits: usize) -> [u16; SUBKEYS] {
    let mut expanded = [0i32; 128];
    for (slot, &byte) in expanded.iter_mut().zip(key) {
        *slot = i32::from(byte);
    }

    let mut len = key.len();
    let mut x = expanded[len - 1];
    if len < expanded.len() {
        let mut index = 0;
        while len < expanded.len() {
            x = i32::from(PI_TABLE[((x + expanded[index]) & 255) as usize]);
            index += 1;
            expanded[len] = x;
            len += 1;
        }
    }

    len = effective_key_bits.div_ceil(8);
    let shift = (7 & (effective_key_bits as i32).wrapping_neg()) as u32;
    let mask = 255i32 >> shift;
    x = i32::from(PI_TABLE[(expanded[128 - len] & mask) as usize]);
    expanded[128 - len] = x;
    for index in (0..128 - len).rev() {
        x = i32::from(PI_TABLE[(x ^ expanded[index + len]) as usize]);
        expanded[index] = x;
    }

    let mut working_key = [0u16; SUBKEYS];
    for (index, word) in working_key.iter_mut().enumerate() {
        *word = (expanded[2 * index] + (expanded[2 * index + 1] << 8)) as u16;
    }
    working_key
}

pub(crate) fn encrypt(working_key: &[u16; SUBKEYS], input: &[u8; 8], output: &mut [u8; 8]) {
    let mut words = read_block(input);
    encrypt_mix(&mut words, working_key, 0, 16);
    encrypt_mash(&mut words, working_key);
    encrypt_mix(&mut words, working_key, 20, 40);
    encrypt_mash(&mut words, working_key);
    encrypt_mix(&mut words, working_key, 44, 60);
    write_block(output, &words);
}

pub(crate) fn decrypt(working_key: &[u16; SUBKEYS], input: &[u8; 8], output: &mut [u8; 8]) {
    let mut words = read_block(input);
    decrypt_mix(&mut words, working_key, 44, 60);
    decrypt_mash(&mut words, working_key);
    decrypt_mix(&mut words, working_key, 20, 40);
    decrypt_mash(&mut words, working_key);
    decrypt_mix(&mut words, working_key, 0, 16);
    write_block(output, &words);
}

fn read_block(input: &[u8; 8]) -> [i32; 4] {
    let mut words = [0i32; 4];
    for (word, bytes) in words.iter_mut().zip(input.chunks_exact(2)) {
        *word = i32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    }
    words
}

fn write_block(output: &mut [u8; 8], words: &[i32; 4]) {
    for (word, bytes) in words.iter().zip(output.chunks_exact_mut(2)) {
        bytes.copy_from_slice(&(*word as u16).to_le_bytes());
    }
}

fn key(working_key: &[u16; SUBKEYS], index: usize) -> i32 {
    i32::from(working_key[index])
}

fn encrypt_mix(words: &mut [i32; 4], working_key: &[u16; SUBKEYS], from: usize, to: usize) {
    for index in (from..=to).step_by(4) {
        words[0] = rotate_left(
            words[0] + (words[1] & !words[3]) + (words[2] & words[3]) + key(working_key, index),
            1,
        );
        words[1] = rotate_left(
            words[1] + (words[2] & !words[0]) + (words[3] & words[0]) + key(working_key, index + 1),
            2,
        );
        words[2] = rotate_left(
            words[2] + (words[3] & !words[1]) + (words[0] & words[1]) + key(working_key, index + 2),
            3,
        );
        words[3] = rotate_left(
            words[3] + (words[0] & !words[2]) + (words[1] & words[2]) + key(working_key, index + 3),
            5,
        );
    }
}

fn encrypt_mash(words: &mut [i32; 4], working_key: &[u16; SUBKEYS]) {
    words[0] += key(working_key, (words[3] & 63) as usize);
    words[1] += key(working_key, (words[0] & 63) as usize);
    words[2] += key(working_key, (words[1] & 63) as usize);
    words[3] += key(working_key, (words[2] & 63) as usize);
}

fn decrypt_mix(words: &mut [i32; 4], working_key: &[u16; SUBKEYS], from: usize, to: usize) {
    for index in (from..=to).rev().step_by(4) {
        words[3] = rotate_left(words[3], 11)
            - ((words[0] & !words[2]) + (words[1] & words[2]) + key(working_key, index + 3));
        words[2] = rotate_left(words[2], 13)
            - ((words[3] & !words[1]) + (words[0] & words[1]) + key(working_key, index + 2));
        words[1] = rotate_left(words[1], 14)
            - ((words[2] & !words[0]) + (words[3] & words[0]) + key(working_key, index + 1));
        words[0] = rotate_left(words[0], 15)
            - ((words[1] & !words[3]) + (words[2] & words[3]) + key(working_key, index));
    }
}

fn decrypt_mash(words: &mut [i32; 4], working_key: &[u16; SUBKEYS]) {
    words[3] -= key(working_key, (words[2] & 63) as usize);
    words[2] -= key(working_key, (words[1] & 63) as usize);
    words[1] -= key(working_key, (words[0] & 63) as usize);
    words[0] -= key(working_key, (words[3] & 63) as usize);
}

fn rotate_left(value: i32, distance: u32) -> i32 {
    i32::from((value as u16).rotate_left(distance))
}
