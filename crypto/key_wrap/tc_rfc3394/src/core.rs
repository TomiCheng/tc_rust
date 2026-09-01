//! Shared RFC 3394 register operations.

use tc_cipher::BlockCipher;

/// Runs the RFC 3394 register loop over an `A || R` block in place.
#[doc(hidden)]
pub fn wrap_core_in_place<C: BlockCipher>(
    cipher: &mut C,
    block: &mut [u8],
) -> Result<(), C::Error> {
    let n = block.len() / 8 - 1;

    if n == 1 {
        crypt_block(cipher, block)?;
        return Ok(());
    }

    let mut buffer = [0u8; 16];
    for j in 0..6u32 {
        for i in 1..=n {
            buffer[..8].copy_from_slice(&block[..8]);
            buffer[8..].copy_from_slice(&block[8 * i..8 * i + 8]);
            crypt_block(cipher, &mut buffer)?;

            xor_counter(&mut buffer[..8], n as u32 * j + i as u32);
            block[..8].copy_from_slice(&buffer[..8]);
            block[8 * i..8 * i + 8].copy_from_slice(&buffer[8..]);
        }
    }
    buffer.fill(0);
    Ok(())
}

/// Unwraps RFC 3394 registers without checking the returned integrity IV.
#[doc(hidden)]
pub fn unwrap_core_into<C: BlockCipher>(
    cipher: &mut C,
    input: &[u8],
    output: &mut [u8],
) -> Result<[u8; 8], C::Error> {
    let n = input.len() / 8 - 1;
    let block = &mut output[..input.len() - 8];
    let mut a = [0u8; 8];
    let mut buffer = [0u8; 16];

    if n == 1 {
        cipher.process_block(&input[..16], &mut buffer)?;
        a.copy_from_slice(&buffer[..8]);
        block[..8].copy_from_slice(&buffer[8..]);
        buffer.fill(0);
        return Ok(a);
    }

    a.copy_from_slice(&input[..8]);
    block.copy_from_slice(&input[8..]);
    for j in (0..6u32).rev() {
        for i in (1..=n).rev() {
            buffer[..8].copy_from_slice(&a);
            buffer[8..].copy_from_slice(&block[8 * (i - 1)..8 * i]);
            xor_counter(&mut buffer[..8], n as u32 * j + i as u32);
            crypt_block(cipher, &mut buffer)?;
            a.copy_from_slice(&buffer[..8]);
            block[8 * (i - 1)..8 * i].copy_from_slice(&buffer[8..]);
        }
    }
    buffer.fill(0);
    Ok(a)
}

#[inline]
fn xor_counter(a: &mut [u8], mut counter: u32) {
    let mut index = 1;
    while counter != 0 {
        a[8 - index] ^= counter as u8;
        counter >>= 8;
        index += 1;
    }
}

fn crypt_block<C: BlockCipher>(cipher: &mut C, block: &mut [u8]) -> Result<(), C::Error> {
    let mut scratch = [0u8; 16];
    cipher.process_block(block, &mut scratch)?;
    block.copy_from_slice(&scratch);
    scratch.fill(0);
    Ok(())
}

/// Constant-time equality for equal-length byte slices.
#[doc(hidden)]
pub fn fixed_time_eq(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}
