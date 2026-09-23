use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

#[cfg(feature = "rustcrypto")]
use crate::AesRustCryptoEngine;
#[cfg(not(feature = "rustcrypto"))]
use crate::AesTableEngine;
#[cfg(all(
    not(feature = "rustcrypto"),
    any(target_arch = "x86", target_arch = "x86_64")
))]
use crate::AesX86Engine;
use crate::BLOCK_BYTES;

enum Inner {
    #[cfg(feature = "rustcrypto")]
    RustCrypto(AesRustCryptoEngine),
    #[cfg(all(
        not(feature = "rustcrypto"),
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    X86(AesX86Engine),
    #[cfg(not(feature = "rustcrypto"))]
    Table(AesTableEngine),
}

/// AES on the safest engine available: `AesRustCryptoEngine` when the
/// `rustcrypto` feature is on, otherwise `AesX86Engine` where the processor
/// has AES-NI, and `AesTableEngine` as the last resort. The table engine is
/// variable time, so without the feature a processor lacking AES-NI leaks
/// through cache timing; enable `rustcrypto` to rule that out.
///
/// The type and its API are the same under every configuration; only the
/// engine inside changes.
///
/// # Example
///
/// Call `init` again to install a new key or change direction.
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
///
/// let mut engine = AesEngine::new();
/// let key = [0x42; 32];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut output = [0; 16];
/// assert_eq!(engine.process_block(&[0; 16], &mut output)?, 16);
/// assert_eq!(engine.to_string(), "AES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct AesEngine {
    inner: Inner,
}

impl core::fmt::Display for AesEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

impl AesEngine {
    /// Picks the engine once, from the feature and the processor. Branches
    /// only on those public facts.
    #[cfg(feature = "rustcrypto")]
    pub fn new() -> Self {
        Self {
            inner: Inner::RustCrypto(AesRustCryptoEngine::new()),
        }
    }

    /// Picks the engine once, from the feature and the processor. Branches
    /// only on those public facts.
    #[cfg(not(feature = "rustcrypto"))]
    pub fn new() -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(engine) = AesX86Engine::new() {
            return Self {
                inner: Inner::X86(engine),
            };
        }
        Self {
            inner: Inner::Table(AesTableEngine::new()),
        }
    }
}

impl Default for AesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AesEngine {
    type Error = InitError;

    /// Initialises the chosen engine; its timing is that engine's.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        match &mut self.inner {
            #[cfg(feature = "rustcrypto")]
            Inner::RustCrypto(engine) => engine.init(direction, params),
            #[cfg(all(
                not(feature = "rustcrypto"),
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            Inner::X86(engine) => engine.init(direction, params),
            #[cfg(not(feature = "rustcrypto"))]
            Inner::Table(engine) => engine.init(direction, params),
        }
    }
}

impl BlockCipher for AesEngine {
    type Error = BlockError;

    /// Always 16. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Delegates to the chosen engine; its timing is that engine's.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        match &mut self.inner {
            #[cfg(feature = "rustcrypto")]
            Inner::RustCrypto(engine) => engine.process_block(input, output),
            #[cfg(all(
                not(feature = "rustcrypto"),
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            Inner::X86(engine) => engine.process_block(input, output),
            #[cfg(not(feature = "rustcrypto"))]
            Inner::Table(engine) => engine.process_block(input, output),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AesEngine;
    use crate::common::test_support as support;

    #[test]
    fn fips_197_vectors_encrypt_and_decrypt_under_every_key_size() {
        support::check_fips_197(AesEngine::new);
    }

    #[test]
    fn processing_before_init_is_rejected() {
        support::check_uninitialised(AesEngine::new);
    }

    #[test]
    fn short_buffers_are_rejected_and_longer_ones_get_exactly_one_block() {
        support::check_buffers(AesEngine::new);
    }

    #[test]
    fn a_rejected_key_length_keeps_the_previous_key() {
        support::check_rejected_key(AesEngine::new);
    }
}
