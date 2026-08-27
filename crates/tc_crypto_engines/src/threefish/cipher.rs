//! The per-variant Threefish round functions.
//!
//! Bouncy Castle expresses the three block sizes as an abstract `ThreefishCipher`
//! with `Threefish256/512/1024Cipher` subclasses, each an 8-round-unrolled
//! `EncryptBlock` / `DecryptBlock`. In Rust that closed set collapses to a single
//! spec-form routine driven by per-variant rotation and permutation tables,
//! selected by [`tables`]. The output is identical to Bouncy Castle's unrolled
//! form (verified against the Skein 1.3 known-answer tests); the unrolling there
//! is purely a speed optimisation.

/// Key-schedule parity constant (Skein 1.3): `C_240`.
pub(super) const C_240: u64 = 0x1BD1_1BDA_A9FC_1A22;

// 旋轉常數表:每列 8 個「輪」(輪數對 8 取模),每輪 nw/2 個字對的旋轉量。
// 攤平存放,索引 rot[(d % 8) * (nw/2) + j]。

#[rustfmt::skip]
const ROT_256: [u32; 16] = [
    14, 16,  52, 57,  23, 40,   5, 37,
    25, 33,  46, 12,  58, 22,  32, 32,
];

#[rustfmt::skip]
const ROT_512: [u32; 32] = [
    46, 36, 19, 37,
    33, 27, 14, 42,
    17, 49, 36, 39,
    44,  9, 54, 56,
    39, 30, 34, 24,
    13, 50, 10, 17,
    25, 29, 39, 43,
     8, 35, 56, 22,
];

#[rustfmt::skip]
const ROT_1024: [u32; 64] = [
    24, 13,  8, 47,  8, 17, 22, 37,
    38, 19, 10, 55, 49, 18, 23, 52,
    33,  4, 51, 13, 34, 41, 59, 17,
     5, 20, 48, 41, 47, 28, 16, 25,
    41,  9, 37, 31, 12, 47, 44, 30,
    16, 34, 56, 51,  4, 53, 42, 41,
    31, 44, 47, 46, 19, 42, 44, 25,
     9, 48, 35, 52, 23, 31, 37, 20,
];

// 字排列 π:每輪 MIX 後 new[i] = old[perm[i]]。
const PERM_256: [usize; 4] = [0, 3, 2, 1];
const PERM_512: [usize; 8] = [2, 1, 4, 7, 6, 5, 0, 3];
const PERM_1024: [usize; 16] = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

/// The constants that distinguish a Threefish block size: word count, round
/// count, rotation table and word permutation.
pub(super) struct Variant {
    /// 分組字數 nw(4 / 8 / 16)。
    pub nw: usize,
    /// 輪數(72 / 72 / 80)。
    pub rounds: usize,
    /// 旋轉表(攤平的 8 × nw/2)。
    pub rot: &'static [u32],
    /// 字排列 π。
    pub perm: &'static [usize],
}

/// Returns the [`Variant`] tables for a validated block size in bytes.
pub(super) fn variant(block_size: usize) -> Variant {
    match block_size {
        32 => Variant { nw: 4, rounds: 72, rot: &ROT_256, perm: &PERM_256 },
        64 => Variant { nw: 8, rounds: 72, rot: &ROT_512, perm: &PERM_512 },
        128 => Variant { nw: 16, rounds: 80, rot: &ROT_1024, perm: &PERM_1024 },
        _ => unreachable!("ThreefishParams validates the key length"),
    }
}

/// One word of subkey `s` (Skein 1.3 key schedule).
///
/// `k` is the extended key (`nw + 1` words, last = `C_240 ^ XOR(key)`); `t` is
/// the 3-word tweak schedule (`t0, t1, t0 ^ t1`).
#[inline]
fn subkey_word(k: &[u64], t: &[u64], nw: usize, s: usize, i: usize) -> u64 {
    let base = k[(s + i) % (nw + 1)];
    if i == nw - 3 {
        base.wrapping_add(t[s % 3])
    } else if i == nw - 2 {
        base.wrapping_add(t[(s + 1) % 3])
    } else if i == nw - 1 {
        base.wrapping_add(s as u64)
    } else {
        base
    }
}

/// Encrypts one block into `out`.
pub(super) fn encrypt(v: &Variant, k: &[u64], t: &[u64], block: &[u64], out: &mut [u64]) {
    let Variant { nw, rounds, rot, perm } = *v;
    let half = nw / 2;
    let mut v = [0u64; 16];
    v[..nw].copy_from_slice(&block[..nw]);

    // 首次 subkey 注入(s = 0)。
    for (i, word) in v[..nw].iter_mut().enumerate() {
        *word = word.wrapping_add(subkey_word(k, t, nw, 0, i));
    }

    for d in 0..rounds {
        let rr = &rot[(d % 8) * half..(d % 8) * half + half];
        // MIX layer:每對 (v[2j], v[2j+1])。
        for j in 0..half {
            let x0 = v[2 * j];
            let x1 = v[2 * j + 1];
            let y0 = x0.wrapping_add(x1);
            v[2 * j] = y0;
            v[2 * j + 1] = x1.rotate_left(rr[j]) ^ y0;
        }
        // 字排列。
        let mut tmp = [0u64; 16];
        for i in 0..nw {
            tmp[i] = v[perm[i]];
        }
        v[..nw].copy_from_slice(&tmp[..nw]);
        // 每 4 輪注入一次 subkey。
        if (d + 1) % 4 == 0 {
            let s = (d + 1) / 4;
            for (i, word) in v[..nw].iter_mut().enumerate() {
                *word = word.wrapping_add(subkey_word(k, t, nw, s, i));
            }
        }
    }

    out[..nw].copy_from_slice(&v[..nw]);
}

/// Decrypts one block into `out` (inverse of [`encrypt`]).
pub(super) fn decrypt(v: &Variant, k: &[u64], t: &[u64], block: &[u64], out: &mut [u64]) {
    let Variant { nw, rounds, rot, perm } = *v;
    let half = nw / 2;
    let mut v = [0u64; 16];
    v[..nw].copy_from_slice(&block[..nw]);

    for d in (0..rounds).rev() {
        // 撤銷該輪之後注入的 subkey。
        if (d + 1) % 4 == 0 {
            let s = (d + 1) / 4;
            for (i, word) in v[..nw].iter_mut().enumerate() {
                *word = word.wrapping_sub(subkey_word(k, t, nw, s, i));
            }
        }
        // 逆字排列:tmp[perm[i]] = v[i]。
        let mut tmp = [0u64; 16];
        for i in 0..nw {
            tmp[perm[i]] = v[i];
        }
        v[..nw].copy_from_slice(&tmp[..nw]);
        // 逆 MIX。
        let rr = &rot[(d % 8) * half..(d % 8) * half + half];
        for j in 0..half {
            let y0 = v[2 * j];
            let y1 = v[2 * j + 1];
            let x1 = (y0 ^ y1).rotate_right(rr[j]);
            v[2 * j] = y0.wrapping_sub(x1);
            v[2 * j + 1] = x1;
        }
    }

    // 撤銷首次 subkey(s = 0)。
    for (i, word) in v[..nw].iter_mut().enumerate() {
        *word = word.wrapping_sub(subkey_word(k, t, nw, 0, i));
    }

    out[..nw].copy_from_slice(&v[..nw]);
}
