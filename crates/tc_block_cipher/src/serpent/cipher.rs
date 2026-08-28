//! Shared Serpent key schedule, bitsliced S-boxes, and round transforms.

pub(super) const ROUNDS: usize = 32;
pub(super) const WORKING_KEY_WORDS: usize = (ROUNDS + 1) * 4;

const PHI: u32 = 0x9e37_79b9;

#[derive(Clone, Copy)]
pub(super) enum Representation {
    Serpent,
    Tnepres,
}

pub(super) fn expand_key(key: &[u8], representation: Representation) -> [u32; WORKING_KEY_WORDS] {
    let mut padded = [0u32; 16];
    let key_words = key.len() / 4;

    match representation {
        Representation::Serpent => {
            for (word, chunk) in padded.iter_mut().zip(key.chunks_exact(4)) {
                *word = u32::from_le_bytes(chunk.try_into().unwrap());
            }
        }
        Representation::Tnepres => {
            for (word, chunk) in padded.iter_mut().zip(key.rchunks_exact(4)) {
                *word = u32::from_be_bytes(chunk.try_into().unwrap());
            }
        }
    }

    if key_words < 8 {
        padded[key_words] = 1;
    }

    for i in 8..16 {
        padded[i] =
            (padded[i - 8] ^ padded[i - 5] ^ padded[i - 3] ^ padded[i - 1] ^ PHI ^ (i as u32 - 8))
                .rotate_left(11);
    }

    let mut working_key = [0u32; WORKING_KEY_WORDS];
    working_key[..8].copy_from_slice(&padded[8..16]);
    for i in 8..WORKING_KEY_WORDS {
        working_key[i] = (working_key[i - 8]
            ^ working_key[i - 5]
            ^ working_key[i - 3]
            ^ working_key[i - 1]
            ^ PHI
            ^ i as u32)
            .rotate_left(11);
    }

    for group in 0..=ROUNDS {
        let offset = group * 4;
        let state = apply_sbox(
            (3usize.wrapping_sub(group)) & 7,
            working_key[offset..offset + 4].try_into().unwrap(),
        );
        working_key[offset..offset + 4].copy_from_slice(&state);
    }

    working_key
}

pub(super) fn encrypt(mut state: [u32; 4], working_key: &[u32; WORKING_KEY_WORDS]) -> [u32; 4] {
    for round in 0..ROUNDS {
        let offset = round * 4;
        for i in 0..4 {
            state[i] ^= working_key[offset + i];
        }
        state = apply_sbox(round & 7, state);
        if round + 1 != ROUNDS {
            state = linear_transform(state);
        }
    }

    for i in 0..4 {
        state[i] ^= working_key[ROUNDS * 4 + i];
    }
    state
}

pub(super) fn decrypt(mut state: [u32; 4], working_key: &[u32; WORKING_KEY_WORDS]) -> [u32; 4] {
    for i in 0..4 {
        state[i] ^= working_key[ROUNDS * 4 + i];
    }

    for round in (0..ROUNDS).rev() {
        state = apply_inverse_sbox(round & 7, state);
        let offset = round * 4;
        for i in 0..4 {
            state[i] ^= working_key[offset + i];
        }
        if round != 0 {
            state = inverse_linear_transform(state);
        }
    }
    state
}

fn apply_sbox(index: usize, [a, b, c, d]: [u32; 4]) -> [u32; 4] {
    match index {
        0 => sb0(a, b, c, d),
        1 => sb1(a, b, c, d),
        2 => sb2(a, b, c, d),
        3 => sb3(a, b, c, d),
        4 => sb4(a, b, c, d),
        5 => sb5(a, b, c, d),
        6 => sb6(a, b, c, d),
        7 => sb7(a, b, c, d),
        _ => unreachable!(),
    }
}

fn apply_inverse_sbox(index: usize, [a, b, c, d]: [u32; 4]) -> [u32; 4] {
    match index {
        0 => ib0(a, b, c, d),
        1 => ib1(a, b, c, d),
        2 => ib2(a, b, c, d),
        3 => ib3(a, b, c, d),
        4 => ib4(a, b, c, d),
        5 => ib5(a, b, c, d),
        6 => ib6(a, b, c, d),
        7 => ib7(a, b, c, d),
        _ => unreachable!(),
    }
}

fn sb0(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = a ^ d;
    let t3 = c ^ t1;
    let t4 = b ^ t3;
    let x3 = (a & d) ^ t4;
    let t7 = a ^ (b & t1);
    let x2 = t4 ^ (c | t7);
    let t12 = x3 & (t3 ^ t7);
    let x1 = !t3 ^ t12;
    let x0 = t12 ^ !t7;
    [x0, x1, x2, x3]
}

fn ib0(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = !a;
    let t2 = a ^ b;
    let t4 = d ^ (t1 | t2);
    let t5 = c ^ t4;
    let x2 = t2 ^ t5;
    let t8 = t1 ^ (d & t2);
    let x1 = t4 ^ (x2 & t8);
    let x3 = (a & t4) ^ (t5 | x1);
    let x0 = x3 ^ (t5 ^ t8);
    [x0, x1, x2, x3]
}

fn sb1(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t2 = b ^ !a;
    let t5 = c ^ (a | t2);
    let x2 = d ^ t5;
    let t7 = b ^ (d | t2);
    let t8 = t2 ^ x2;
    let x3 = t8 ^ (t5 & t7);
    let t11 = t5 ^ t7;
    let x1 = x3 ^ t11;
    let x0 = t5 ^ (t8 & t11);
    [x0, x1, x2, x3]
}

fn ib1(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = b ^ d;
    let t3 = a ^ (b & t1);
    let t4 = t1 ^ t3;
    let x3 = c ^ t4;
    let t7 = b ^ (t1 & t3);
    let t8 = x3 | t7;
    let x1 = t3 ^ t8;
    let t10 = !x1;
    let t11 = x3 ^ t7;
    let x0 = t10 ^ t11;
    let x2 = t4 ^ (t10 | t11);
    [x0, x1, x2, x3]
}

fn sb2(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = !a;
    let t2 = b ^ d;
    let t3 = c & t1;
    let x0 = t2 ^ t3;
    let t5 = c ^ t1;
    let t6 = c ^ x0;
    let t7 = b & t6;
    let x3 = t5 ^ t7;
    let x2 = a ^ ((d | t7) & (x0 | t5));
    let x1 = (t2 ^ x3) ^ (x2 ^ (d | t1));
    [x0, x1, x2, x3]
}

fn ib2(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = b ^ d;
    let t2 = !t1;
    let t3 = a ^ c;
    let t4 = c ^ t1;
    let t5 = b & t4;
    let x0 = t3 ^ t5;
    let t7 = a | t2;
    let t8 = d ^ t7;
    let t9 = t3 | t8;
    let x3 = t1 ^ t9;
    let t11 = !t4;
    let t12 = x0 | x3;
    let x1 = t11 ^ t12;
    let x2 = (d & t11) ^ (t3 ^ t12);
    [x0, x1, x2, x3]
}

fn sb3(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = a ^ b;
    let t2 = a & c;
    let t3 = a | d;
    let t4 = c ^ d;
    let t5 = t1 & t3;
    let t6 = t2 | t5;
    let x2 = t4 ^ t6;
    let t8 = b ^ t3;
    let t9 = t6 ^ t8;
    let t10 = t4 & t9;
    let x0 = t1 ^ t10;
    let t12 = x2 & x0;
    let x1 = t9 ^ t12;
    let x3 = (b | d) ^ (t4 ^ t12);
    [x0, x1, x2, x3]
}

fn ib3(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = a | b;
    let t2 = b ^ c;
    let t3 = b & t2;
    let t4 = a ^ t3;
    let t5 = c ^ t4;
    let t6 = d | t4;
    let x0 = t2 ^ t6;
    let t8 = t2 | t6;
    let t9 = d ^ t8;
    let x2 = t5 ^ t9;
    let t11 = t1 ^ t9;
    let t12 = x0 & t11;
    let x3 = t4 ^ t12;
    let x1 = x3 ^ (x0 ^ t11);
    [x0, x1, x2, x3]
}

fn sb4(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = a ^ d;
    let t2 = d & t1;
    let t3 = c ^ t2;
    let t4 = b | t3;
    let x3 = t1 ^ t4;
    let t6 = !b;
    let t7 = t1 | t6;
    let x0 = t3 ^ t7;
    let t9 = a & x0;
    let t10 = t1 ^ t6;
    let t11 = t4 & t10;
    let x2 = t9 ^ t11;
    let x1 = (a ^ t3) ^ (t10 & x2);
    [x0, x1, x2, x3]
}

fn ib4(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = c | d;
    let t2 = a & t1;
    let t3 = b ^ t2;
    let t4 = a & t3;
    let t5 = c ^ t4;
    let x1 = d ^ t5;
    let t7 = !a;
    let t8 = t5 & x1;
    let x3 = t3 ^ t8;
    let t10 = x1 | t7;
    let t11 = d ^ t10;
    let x0 = x3 ^ t11;
    let x2 = (t3 & t11) ^ (x1 ^ t7);
    [x0, x1, x2, x3]
}

fn sb5(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = !a;
    let t2 = a ^ b;
    let t3 = a ^ d;
    let t4 = c ^ t1;
    let t5 = t2 | t3;
    let x0 = t4 ^ t5;
    let t7 = d & x0;
    let t8 = t2 ^ x0;
    let x1 = t7 ^ t8;
    let t10 = t1 | x0;
    let t11 = t2 | t7;
    let t12 = t3 ^ t10;
    let x2 = t11 ^ t12;
    let x3 = (b ^ t7) ^ (x1 & t12);
    [x0, x1, x2, x3]
}

fn ib5(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = !c;
    let t2 = b & t1;
    let t3 = d ^ t2;
    let t4 = a & t3;
    let t5 = b ^ t1;
    let x3 = t4 ^ t5;
    let t7 = b | x3;
    let t8 = a & t7;
    let x1 = t3 ^ t8;
    let t10 = a | d;
    let t11 = t1 ^ t7;
    let x0 = t10 ^ t11;
    let x2 = (b & t10) ^ (t4 | (a ^ c));
    [x0, x1, x2, x3]
}

fn sb6(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = !a;
    let t2 = a ^ d;
    let t3 = b ^ t2;
    let t4 = t1 | t2;
    let t5 = c ^ t4;
    let x1 = b ^ t5;
    let t7 = t2 | x1;
    let t8 = d ^ t7;
    let t9 = t5 & t8;
    let x2 = t3 ^ t9;
    let t11 = t5 ^ t8;
    let x0 = x2 ^ t11;
    let x3 = !t5 ^ (t3 & t11);
    [x0, x1, x2, x3]
}

fn ib6(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = !a;
    let t2 = a ^ b;
    let t3 = c ^ t2;
    let t4 = c | t1;
    let t5 = d ^ t4;
    let x1 = t3 ^ t5;
    let t7 = t3 & t5;
    let t8 = t2 ^ t7;
    let t9 = b | t8;
    let x3 = t5 ^ t9;
    let t11 = b | x3;
    let x0 = t8 ^ t11;
    let x2 = (d & t1) ^ (t3 ^ t11);
    [x0, x1, x2, x3]
}

fn sb7(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t1 = b ^ c;
    let t2 = c & t1;
    let t3 = d ^ t2;
    let t4 = a ^ t3;
    let t5 = d | t1;
    let t6 = t4 & t5;
    let x1 = b ^ t6;
    let t8 = t3 | x1;
    let t9 = a & t4;
    let x3 = t1 ^ t9;
    let t11 = t4 ^ t8;
    let t12 = x3 & t11;
    let x2 = t3 ^ t12;
    let x0 = !t11 ^ (x3 & x2);
    [x0, x1, x2, x3]
}

fn ib7(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let t3 = c | (a & b);
    let t4 = d & (a | b);
    let x3 = t3 ^ t4;
    let t6 = !d;
    let t7 = b ^ t4;
    let t9 = t7 | (x3 ^ t6);
    let x1 = a ^ t9;
    let x0 = (c ^ t7) ^ (d | x1);
    let x2 = (t3 ^ x1) ^ (x0 ^ (a & x3));
    [x0, x1, x2, x3]
}

fn linear_transform([a, b, c, d]: [u32; 4]) -> [u32; 4] {
    let x0 = a.rotate_left(13);
    let x2 = c.rotate_left(3);
    let x1 = b ^ x0 ^ x2;
    let x3 = d ^ x2 ^ (x0 << 3);
    let x1 = x1.rotate_left(1);
    let x3 = x3.rotate_left(7);
    [
        (x0 ^ x1 ^ x3).rotate_left(5),
        x1,
        (x2 ^ x3 ^ (x1 << 7)).rotate_left(22),
        x3,
    ]
}

fn inverse_linear_transform([a, b, c, d]: [u32; 4]) -> [u32; 4] {
    let x2 = c.rotate_right(22) ^ d ^ (b << 7);
    let x0 = a.rotate_right(5) ^ b ^ d;
    let x3 = d.rotate_right(7);
    let x1 = b.rotate_right(1);
    [
        x0.rotate_right(13),
        x1 ^ x0 ^ x2,
        x2.rotate_right(3),
        x3 ^ x2 ^ (x0 << 3),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sbox_has_a_working_inverse() {
        let inputs = [
            [0, 0, 0, 0],
            [u32::MAX, 0, 0x5555_5555, 0xaaaa_aaaa],
            [0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210],
        ];
        for index in 0..8 {
            for input in inputs {
                assert_eq!(apply_inverse_sbox(index, apply_sbox(index, input)), input);
            }
        }
    }

    #[test]
    fn linear_transform_has_a_working_inverse() {
        let input = [0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210];
        assert_eq!(inverse_linear_transform(linear_transform(input)), input);
    }
}
