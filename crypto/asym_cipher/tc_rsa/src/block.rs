//! What the RSA engines share about blocks: their sizes, and how a result
//! is written out.

use tc_asym_cipher::CipherDirection;
use tc_bigint::BitOps;

/// The input block of a modulus of `bits` bits: `(bits - 1) / 8` bytes when
/// encrypting, so that any input is below the modulus, and `(bits + 7) / 8`
/// when decrypting. Constant time.
pub(crate) fn input_block_size(bits: u32, direction: CipherDirection) -> usize {
    match direction {
        CipherDirection::Encrypt => (bits as usize - 1) / 8,
        CipherDirection::Decrypt => (bits as usize).div_ceil(8),
    }
}

/// The output block of a modulus of `bits` bits: its full length,
/// `(bits + 7) / 8` bytes, in both directions. Constant time.
pub(crate) fn output_block_size(bits: u32) -> usize {
    (bits as usize).div_ceil(8)
}

/// `value` big-endian over all of `output`, which holds it, bit by bit, so
/// that no buffer is needed whatever the width of `T`. As constant time as
/// the `bit` of `T` is: the bits read follow the length of `output`.
pub(crate) fn write_be<T: BitOps>(value: &T, output: &mut [u8]) {
    let length = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        let low = 8 * (length - 1 - index) as u32;
        *byte = (0..8).fold(0, |byte, bit| {
            byte | (u8::from(value.bit(low + bit)) << bit)
        });
    }
}
