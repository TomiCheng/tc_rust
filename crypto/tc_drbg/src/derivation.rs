//! SP 800-90A 的 derivation functions。

use alloc::{vec, vec::Vec};

use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_digest::Digest;
use tc_params::KeyRef;

use crate::DrbgError;

const AES_BLOCK_SIZE: usize = 16;
const K_BITS: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

pub(crate) fn max_hash_security_strength(output_size: usize) -> Result<usize, DrbgError> {
    match output_size {
        20 => Ok(128),
        28 => Ok(192),
        32 | 48 | 64 => Ok(256),
        _ => Err(DrbgError::UnsupportedOutputSize(output_size)),
    }
}

pub(crate) const fn hash_seed_length(output_size: usize) -> usize {
    if output_size <= 32 { 440 } else { 888 }
}

pub(crate) fn hash_df<D: Digest>(
    digest: &mut D,
    input: &[u8],
    output_bits: usize,
) -> Result<Vec<u8>, DrbgError> {
    let output_bits = u32::try_from(output_bits).map_err(|_| DrbgError::InputTooLong)?;
    let output_len = (output_bits as usize).div_ceil(8);
    let digest_size = digest.digest_size();
    if digest_size == 0 {
        return Err(DrbgError::UnsupportedOutputSize(0));
    }

    let mut output = vec![0_u8; output_len];
    let mut hash = vec![0_u8; digest_size];
    let mut offset = 0;
    let mut counter = 1_u8;
    while offset < output_len {
        digest.update_byte(counter);
        digest.update(&output_bits.to_be_bytes());
        digest.update(input);
        let written = digest.do_final(&mut hash);
        debug_assert_eq!(written, digest_size);

        let take = core::cmp::min(digest_size, output_len - offset);
        output[offset..offset + take].copy_from_slice(&hash[..take]);
        offset += take;
        counter = counter.checked_add(1).ok_or(DrbgError::InputTooLong)?;
    }

    let excess = (8 - output_bits as usize % 8) % 8;
    if excess != 0 {
        let mut carry = 0_u8;
        for byte in &mut output {
            let current = *byte;
            *byte = (current >> excess) | carry;
            carry = current << (8 - excess);
        }
    }
    Ok(output)
}

pub(crate) fn block_cipher_df<C>(
    cipher: &mut C,
    key_size: usize,
    input: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, DrbgError>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    let input_len = u32::try_from(input.len()).map_err(|_| DrbgError::InputTooLong)?;
    let requested_len = u32::try_from(output_len).map_err(|_| DrbgError::InputTooLong)?;
    if cipher.block_size() != AES_BLOCK_SIZE {
        return Err(DrbgError::InvalidBlockSize(cipher.block_size()));
    }

    let data_len = 8_usize
        .checked_add(input.len())
        .and_then(|length| length.checked_add(1))
        .ok_or(DrbgError::InputTooLong)?;
    let padded_len = data_len
        .div_ceil(AES_BLOCK_SIZE)
        .checked_mul(AES_BLOCK_SIZE)
        .ok_or(DrbgError::InputTooLong)?;
    let mut s = vec![0_u8; padded_len];
    s[..4].copy_from_slice(&input_len.to_be_bytes());
    s[4..8].copy_from_slice(&requested_len.to_be_bytes());
    s[8..8 + input.len()].copy_from_slice(input);
    s[8 + input.len()] = 0x80;

    let initial_key = &K_BITS[..key_size];
    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(initial_key))
        .map_err(|_| DrbgError::CipherFailure)?;

    let temp_len = key_size + AES_BLOCK_SIZE;
    let mut temp = vec![0_u8; temp_len];
    let mut offset = 0;
    let mut counter = 0_u32;
    while offset < temp_len {
        let mut iv = [0_u8; AES_BLOCK_SIZE];
        iv[..4].copy_from_slice(&counter.to_be_bytes());
        let block = bcc(cipher, &iv, &s)?;
        let take = core::cmp::min(AES_BLOCK_SIZE, temp_len - offset);
        temp[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        counter = counter.checked_add(1).ok_or(DrbgError::InputTooLong)?;
    }

    let key = temp[..key_size].to_vec();
    let mut x = temp[key_size..key_size + AES_BLOCK_SIZE].to_vec();
    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(&key))
        .map_err(|_| DrbgError::CipherFailure)?;

    let mut output = vec![0_u8; output_len];
    for chunk in output.chunks_mut(AES_BLOCK_SIZE) {
        let mut next = [0_u8; AES_BLOCK_SIZE];
        let written = cipher
            .process_block(&x, &mut next)
            .map_err(|_| DrbgError::CipherFailure)?;
        if written != AES_BLOCK_SIZE {
            return Err(DrbgError::CipherFailure);
        }
        x.copy_from_slice(&next);
        chunk.copy_from_slice(&next[..chunk.len()]);
    }
    Ok(output)
}

fn bcc<C>(cipher: &mut C, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, DrbgError>
where
    C: BlockCipher,
{
    let block_size = cipher.block_size();
    let mut chaining = vec![0_u8; block_size];
    let mut input_block = vec![0_u8; block_size];

    for block in core::iter::once(iv).chain(data.chunks_exact(block_size)) {
        for ((target, left), right) in input_block.iter_mut().zip(&chaining).zip(block) {
            *target = *left ^ *right;
        }
        let written = cipher
            .process_block(&input_block, &mut chaining)
            .map_err(|_| DrbgError::CipherFailure)?;
        if written != block_size {
            return Err(DrbgError::CipherFailure);
        }
    }
    Ok(chaining)
}
