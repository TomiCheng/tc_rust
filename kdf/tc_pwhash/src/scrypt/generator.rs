use alloc::vec;
use alloc::vec::Vec;

use tc_pbe::{PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S2};
use tc_sha::Sha256Digest;
use tc_zeroize::Zeroizing;

use super::ScryptError;
use super::ro_mix::ro_mix;

/// scrypt of RFC 7914, BC's `SCrypt`: PBKDF2-HMAC-SHA256 spreads the password over `p`
/// blocks, ROMix mixes each through `N` steps of memory, and a second PBKDF2 turns them into
/// the key.
pub struct Scrypt;

impl Scrypt {
    /// Fills `key` with scrypt of `password` and `salt`, BC's `Generate(P, S, N, r, p, dkLen)`:
    /// `n` is the cost `N`, `r` the block size and `p` the parallelization, run in turn here.
    ///
    /// Needs `128 * r * n` bytes for ROMix's table and `128 * r * p` for the blocks. Fails, as in
    /// BC, when `n` is not a power of two above 1 (below 65536 when `r` is 1), `r` is 0, `p` is 0
    /// or above `(2^31 - 1) / (1024 * r)`, or `key` is empty; and when the table cannot be
    /// allocated, before any work.
    ///
    /// **Variable time (cache timing):** ROMix's second half reads its table at indices taken
    /// from the state, which depends on the password; that is how scrypt makes itself
    /// memory-hard, and where a cache is shared the timing can leak about the password. The rest
    /// depends only on `n`, `r`, `p` and the lengths. There is no constant-time form. Every
    /// working buffer is wiped before returning.
    pub fn generate(
        password: &[u8],
        salt: &[u8],
        n: u32,
        r: u32,
        p: u32,
        key: &mut [u8],
    ) -> Result<(), ScryptError> {
        if n < 2 || !n.is_power_of_two() || (r == 1 && n >= 65536) {
            return Err(ScryptError::InvalidCost(n));
        }
        if r == 0 {
            return Err(ScryptError::InvalidBlockSize(r));
        }
        let max_parallel = i32::MAX as u64 / (1024 * u64::from(r));
        if p == 0 || u64::from(p) > max_parallel {
            return Err(ScryptError::InvalidParallelism(p));
        }
        if key.is_empty() {
            return Err(ScryptError::EmptyOutput);
        }

        let block_words = 32 * r as usize;
        let table_words = (n as usize)
            .checked_mul(block_words)
            .ok_or(ScryptError::OutOfMemory)?;
        let mut table = Zeroizing::new(Vec::new());
        table
            .try_reserve_exact(table_words)
            .map_err(|_| ScryptError::OutOfMemory)?;
        table.resize(table_words, 0);

        let mut bytes = Zeroizing::new(vec![0; p as usize * block_words * 4]);
        pbkdf2(password, salt, &mut bytes)?;
        let mut blocks: Zeroizing<Vec<u32>> = Zeroizing::new(
            bytes
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
                .collect(),
        );
        let mut scratch = Zeroizing::new(vec![0; block_words]);
        for block in blocks.chunks_exact_mut(block_words) {
            ro_mix(block, &mut table, &mut scratch, n as usize);
        }
        for (word_bytes, word) in bytes.chunks_exact_mut(4).zip(blocks.iter()) {
            word_bytes.copy_from_slice(&word.to_le_bytes());
        }
        pbkdf2(password, &bytes, key)
    }
}

fn pbkdf2(password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), ScryptError> {
    let mut generator = Pkcs5S2::new(Sha256Digest::new());
    generator
        .init(&PbeParamsRef::new(password, salt, 1))
        .map_err(ScryptError::Pbkdf2)?;
    generator.derive_key(out).map_err(ScryptError::Pbkdf2)
}
