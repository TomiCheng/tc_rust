use tc_zeroize::Zeroize;

use super::salsa::salsa20_8;

/// RFC 7914 的 scryptBlockMix：`input` 與 `output` 各 2r 個 16 字的區塊。
fn block_mix(input: &[u32], output: &mut [u32]) {
    let r = input.len() / 32;
    let mut x = [0; 16];
    x.copy_from_slice(&input[input.len() - 16..]);
    for (i, block) in input.chunks_exact(16).enumerate() {
        for (x, b) in x.iter_mut().zip(block) {
            *x ^= b;
        }
        salsa20_8(&mut x);
        let at = (i / 2 + (i % 2) * r) * 16;
        output[at..at + 16].copy_from_slice(&x);
    }
    x.zeroize();
}

/// RFC 7914 的 scryptROMix，就地改 `block`；`v` 長 `n` 個 `block`，`scratch` 一個。
/// BC 把 `v` 切成不超過 32 KiB 的塊只是 .NET 的配置考量，這裡一次配置。
pub(super) fn ro_mix(block: &mut [u32], v: &mut [u32], scratch: &mut [u32], n: usize) {
    let len = block.len();
    for entry in v.chunks_exact_mut(len) {
        entry.copy_from_slice(block);
        block_mix(entry, block);
    }
    for _ in 0..n {
        // Integerify：最後一個 64 位元組區塊的第一個字；n 不超過 2^31，取一個字就夠
        let j = block[len - 16] as usize & (n - 1);
        let entry = &v[j * len..(j + 1) * len];
        for ((s, x), v) in scratch.iter_mut().zip(block.iter()).zip(entry) {
            *s = x ^ v;
        }
        block_mix(scratch, block);
    }
}
