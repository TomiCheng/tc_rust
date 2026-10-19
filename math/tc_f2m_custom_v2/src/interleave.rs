// BC's `Interleave.Expand64To128`: bit i of `x` becomes bit 2i of the 128-bit result.
pub(crate) fn expand64_to128(mut x: u64) -> [u64; 2] {
    const M64: u64 = 0x5555_5555_5555_5555;
    x = bit_permute_step(x, 0x0000_0000_FFFF_0000, 16);
    x = bit_permute_step(x, 0x0000_FF00_0000_FF00, 8);
    x = bit_permute_step(x, 0x00F0_00F0_00F0_00F0, 4);
    x = bit_permute_step(x, 0x0C0C_0C0C_0C0C_0C0C, 2);
    x = bit_permute_step(x, 0x2222_2222_2222_2222, 1);
    [x & M64, (x >> 1) & M64]
}

// BC's `Bits.BitPermuteStep`: swaps the bits under `mask` with those `shift` above them.
fn bit_permute_step(x: u64, mask: u64, shift: u32) -> u64 {
    let t = (x ^ (x >> shift)) & mask;
    t ^ (t << shift) ^ x
}
