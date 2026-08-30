//! RFC 3394 AES Key Wrap engine, generic over the underlying block cipher.
//!
//! See RFC 3394 (Schaad & Housley, 2002). This type is the shared base for
//! concrete wrappers such as `AesWrapEngine`, mirroring Bouncy Castle's
//! `Rfc3394WrapEngine`. The register loop is factored into caller-buffer cores;
//! allocation-backed adapters remain available so that the RFC 5649 wrapper
//! ([`crate::rfc5649`]) can reuse the same implementation.

use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto_core::Wrapper;

/// The RFC 3394 default IV (`0xA6` repeated eight times).
const DEFAULT_IV: [u8; 8] = [0xa6; 8];

/// Parameters for an RFC 3394 wrapper: the underlying engine's key parameters
/// plus an optional custom IV.
///
/// The caller builds the underlying engine's parameters (e.g.
/// `AesParams::new(kek)`) and hands them in, so the generic wrapper needs no
/// separate "key from bytes" capability trait.
pub struct Rfc3394Params<'a, E: BlockCipherInit> {
    /// The underlying block cipher's key parameters (e.g. `AesParams`).
    key_params: <E as BlockCipherInit>::Params<'a>,
    /// A custom IV; `None` uses the RFC 3394 default IV.
    iv: Option<[u8; 8]>,
}

impl<'a, E: BlockCipherInit> Rfc3394Params<'a, E> {
    /// Builds parameters from the engine's key parameters, using the RFC 3394
    /// default IV.
    pub fn new(key_params: <E as BlockCipherInit>::Params<'a>) -> Self {
        Self {
            key_params,
            iv: None,
        }
    }

    /// Builds parameters from the engine's key parameters and a custom 8-byte IV.
    pub fn with_iv(key_params: <E as BlockCipherInit>::Params<'a>, iv: [u8; 8]) -> Self {
        Self {
            key_params,
            iv: Some(iv),
        }
    }
}

/// RFC 3394 AES Key Wrap, generic over the underlying block cipher `E`.
///
/// Mirrors bc's `Rfc3394WrapEngine`. Inject the underlying engine (which must
/// have a 128-bit block) with [`new`](Self::new), then wrap / unwrap through the
/// allocation-free [`KeyWrap`] interface. The legacy allocation-backed
/// [`Wrapper`] interface remains available during migration.
pub struct Rfc3394WrapEngine<E: BlockCipher> {
    /// The underlying block cipher engine.
    engine: E,
    /// Engine direction used when wrapping (= `!use_reverse_direction`); unwrap
    /// uses the opposite.
    wrap_cipher_mode: bool,
    /// The IV in use (chosen at `init`, defaulting to [`DEFAULT_IV`]).
    iv: [u8; 8],
    /// The key-level operation selected during initialization.
    direction: Option<WrapDirection>,
}

impl<E: BlockCipher> Rfc3394WrapEngine<E> {
    /// Builds a wrapper over the given engine (forward: wrapping uses the
    /// engine's encryption direction).
    pub fn new(engine: E) -> Self {
        Self::with_reverse_direction(engine, false)
    }

    /// Builds a wrapper, choosing whether to reverse the underlying cipher
    /// direction (bc's `useReverseDirection`; used by a few schemes such as RC2).
    pub fn with_reverse_direction(engine: E, use_reverse_direction: bool) -> Self {
        assert_eq!(
            engine.block_size(),
            16,
            "RFC 3394 requires a 128-bit (16-byte) block, but {} has a {}-byte block",
            engine.algorithm_name(),
            engine.block_size(),
        );

        Self {
            engine,
            wrap_cipher_mode: !use_reverse_direction,
            iv: DEFAULT_IV,
            direction: None,
        }
    }
}

/// Builds the wrapper over a freshly constructed underlying engine
/// (`E::default()`), so the concrete aliases can be created with no arguments
/// (e.g. `AesWrapEngine::default()`).
impl<E: BlockCipher + Default> Default for Rfc3394WrapEngine<E> {
    fn default() -> Self {
        Self::new(E::default())
    }
}

/// Error type for the RFC 3394 wrapper.
pub enum Rfc3394Error<E: BlockCipher> {
    /// wrap / unwrap called before `init`.
    Uninitialised,
    /// Initialised for unwrapping, but `wrap` was called.
    NotForWrapping,
    /// Initialised for wrapping, but `unwrap` was called.
    NotForUnwrapping,
    /// Invalid wrap input length (must be at least 8 and a multiple of 8).
    WrapDataLength,
    /// Invalid unwrap input length (must be at least 16 and a multiple of 8).
    UnwrapDataLength,
    /// The caller-provided output buffer is shorter than the required length.
    OutputBufferTooShort {
        /// Required output capacity in bytes.
        required: usize,
        /// Available output capacity in bytes.
        available: usize,
    },
    /// Integrity check failed on unwrap (tampered data or wrong key).
    IntegrityCheckFailed,
    /// Error reported by the underlying block cipher engine.
    BlockCipher(E::Error),
}

// 泛型 enum 的 Debug 手寫，不用 derive：derive 會對型別參數加上 `E: Debug`
// 約束（錯的對象），而我們真正需要的是 `E::Error: Debug`——這由 BlockCipher
// 的 `type Error: core::error::Error`（其 supertrait 含 Debug）保證。
impl<E: BlockCipher> core::fmt::Debug for Rfc3394Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Rfc3394Error::Uninitialised => f.write_str("Uninitialised"),
            Rfc3394Error::NotForWrapping => f.write_str("NotForWrapping"),
            Rfc3394Error::NotForUnwrapping => f.write_str("NotForUnwrapping"),
            Rfc3394Error::WrapDataLength => f.write_str("WrapDataLength"),
            Rfc3394Error::UnwrapDataLength => f.write_str("UnwrapDataLength"),
            Rfc3394Error::OutputBufferTooShort {
                required,
                available,
            } => f
                .debug_struct("OutputBufferTooShort")
                .field("required", required)
                .field("available", available)
                .finish(),
            Rfc3394Error::IntegrityCheckFailed => f.write_str("IntegrityCheckFailed"),
            Rfc3394Error::BlockCipher(e) => f.debug_tuple("BlockCipher").field(e).finish(),
        }
    }
}

impl<E: BlockCipher> core::fmt::Display for Rfc3394Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Rfc3394Error::Uninitialised => f.write_str("key wrapper not initialised"),
            Rfc3394Error::NotForWrapping => f.write_str("wrapper not set for wrapping"),
            Rfc3394Error::NotForUnwrapping => f.write_str("wrapper not set for unwrapping"),
            Rfc3394Error::WrapDataLength => {
                f.write_str("wrap data must be at least 8 bytes and a multiple of 8")
            }
            Rfc3394Error::UnwrapDataLength => {
                f.write_str("unwrap data must be at least 16 bytes and a multiple of 8")
            }
            Rfc3394Error::OutputBufferTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Rfc3394Error::IntegrityCheckFailed => f.write_str("integrity check failed"),
            Rfc3394Error::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl<E: BlockCipher> core::error::Error for Rfc3394Error<E> {}

impl<E: BlockCipherInit> Rfc3394WrapEngine<E> {
    /// Keys the underlying block cipher and records the key-level direction.
    fn initialize(
        &mut self,
        direction: WrapDirection,
        params: &Rfc3394Params<'_, E>,
    ) -> Result<(), Rfc3394Error<E>> {
        // Wrap normally uses encryption and unwrap uses decryption. The optional
        // reverse-direction construction swaps those underlying cipher modes.
        let for_encryption = match direction {
            WrapDirection::Wrap => self.wrap_cipher_mode,
            WrapDirection::Unwrap => !self.wrap_cipher_mode,
        };
        let cipher_direction = if for_encryption {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };

        self.engine
            .init(cipher_direction, &params.key_params)
            .map_err(Rfc3394Error::BlockCipher)?;

        self.iv = params.iv.unwrap_or(DEFAULT_IV);
        self.direction = Some(direction);
        Ok(())
    }
}

impl<E: BlockCipher> KeyWrap for Rfc3394WrapEngine<E> {
    type Error = Rfc3394Error<E>;

    fn algorithm_name(&self) -> &str {
        self.engine.algorithm_name()
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len < 8 || !input_len.is_multiple_of(8) {
            return Err(Rfc3394Error::WrapDataLength);
        }
        input_len.checked_add(8).ok_or(Rfc3394Error::WrapDataLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len < 16 || !input_len.is_multiple_of(8) {
            return Err(Rfc3394Error::UnwrapDataLength);
        }
        Ok(input_len - 8)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(Rfc3394Error::NotForWrapping),
            None => return Err(Rfc3394Error::Uninitialised),
        }

        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc3394Error::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        let iv = self.iv;
        wrap_core_into(&mut self.engine, &iv, input, &mut output[..required])
            .map_err(Rfc3394Error::BlockCipher)?;
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Rfc3394Error::NotForUnwrapping),
            None => return Err(Rfc3394Error::Uninitialised),
        }

        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc3394Error::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        let a = match unwrap_core_into(&mut self.engine, input, &mut output[..required]) {
            Ok(a) => a,
            Err(error) => {
                output[..required].fill(0);
                return Err(Rfc3394Error::BlockCipher(error));
            }
        };

        // Reject a wrong key or tampered blob without leaving recovered,
        // unauthenticated key material in the caller's output buffer.
        if !fixed_time_eq(&a, &self.iv) {
            output[..required].fill(0);
            return Err(Rfc3394Error::IntegrityCheckFailed);
        }
        Ok(required)
    }
}

impl<E: BlockCipherInit> KeyWrapInit for Rfc3394WrapEngine<E> {
    type Params<'a> = Rfc3394Params<'a, E>;

    fn init(
        &mut self,
        direction: WrapDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.initialize(direction, params)
    }
}

impl<E: BlockCipherInit> Wrapper for Rfc3394WrapEngine<E> {
    type Params<'a> = Rfc3394Params<'a, E>;
    type Error = Rfc3394Error<E>;

    fn algorithm_name(&self) -> &str {
        KeyWrap::algorithm_name(self)
    }

    fn init(&mut self, for_wrapping: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        let direction = if for_wrapping {
            WrapDirection::Wrap
        } else {
            WrapDirection::Unwrap
        };
        self.initialize(direction, params)
    }

    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let required = KeyWrap::wrapped_len(self, input.len())?;
        let mut output = vec![0_u8; required];
        let written = KeyWrap::wrap_into(self, input, &mut output)?;
        debug_assert_eq!(written, required);
        Ok(output)
    }

    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let capacity = KeyWrap::max_unwrapped_len(self, input.len())?;
        let mut output = vec![0_u8; capacity];
        let written = KeyWrap::unwrap_into(self, input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }
}

/// RFC 3394 wrap core: runs the A/R register loop on an already-keyed
/// (encryption-direction) engine. `iv` is the 8-byte AIV/IV and `input` must be
/// a positive multiple of 8 bytes (the caller checks this). Shared by the RFC
/// 3394 and RFC 5649 wrappers.
pub(crate) fn wrap_core<E: BlockCipher>(
    engine: &mut E,
    iv: &[u8; 8],
    input: &[u8],
) -> Result<Vec<u8>, E::Error> {
    let mut output = vec![0_u8; input.len() + 8];
    wrap_core_into(engine, iv, input, &mut output)?;
    Ok(output)
}

/// Caller-buffer RFC 3394 wrap core shared by the allocation-free interface
/// and the allocation-backed compatibility adapter.
fn wrap_core_into<E: BlockCipher>(
    engine: &mut E,
    iv: &[u8; 8],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), E::Error> {
    let n = input.len() / 8;
    let block = &mut output[..input.len() + 8];

    // block = IV(8) || input，之後所有運算就地在 block 上進行。
    block[..8].copy_from_slice(iv);
    block[8..].copy_from_slice(input);

    if n == 1 {
        // 單一資料分組：直接加密 IV||R 這 16 bytes。
        crypt_block(engine, block)?;
    } else {
        let mut buf = [0u8; 16];
        for j in 0..6u32 {
            for i in 1..=n {
                buf[..8].copy_from_slice(&block[..8]);
                buf[8..].copy_from_slice(&block[8 * i..8 * i + 8]);
                crypt_block(engine, &mut buf)?;

                // t = n*j + i，逐位元組 XOR 進 A 暫存（buf 的前半）。
                let mut t = n as u32 * j + i as u32;
                let mut k = 1;
                while t != 0 {
                    buf[8 - k] ^= t as u8;
                    t >>= 8;
                    k += 1;
                }

                block[..8].copy_from_slice(&buf[..8]);
                block[8 * i..8 * i + 8].copy_from_slice(&buf[8..]);
            }
        }
    }

    Ok(())
}

/// RFC 3394 unwrap core, **without** the IV check: returns `(data, extracted A)`.
/// The caller validates the extracted A (RFC 3394 compares it to the IV; RFC 5649
/// decodes the AIV and MLI from it). `input` must be at least 16 bytes and a
/// multiple of 8 (the caller checks this).
pub(crate) fn unwrap_core<E: BlockCipher>(
    engine: &mut E,
    input: &[u8],
) -> Result<(Vec<u8>, [u8; 8]), E::Error> {
    let mut output = vec![0_u8; input.len() - 8];
    let a = unwrap_core_into(engine, input, &mut output)?;
    Ok((output, a))
}

/// Caller-buffer RFC 3394 unwrap core without the IV integrity check.
fn unwrap_core_into<E: BlockCipher>(
    engine: &mut E,
    input: &[u8],
    output: &mut [u8],
) -> Result<[u8; 8], E::Error> {
    // 資料分組數（扣掉開頭的 A 暫存那 8 bytes）。
    let n = input.len() / 8 - 1;

    let block = &mut output[..input.len() - 8];
    let mut a = [0u8; 8];
    let mut buf = [0u8; 16];

    if n == 1 {
        // 單一資料分組：解密開頭 16 bytes，前半為 A、後半為資料。
        engine.process_block(&input[..16], &mut buf)?;
        a.copy_from_slice(&buf[..8]);
        block[..8].copy_from_slice(&buf[8..]);
    } else {
        a.copy_from_slice(&input[..8]);
        block.copy_from_slice(&input[8..]);

        for j in (0..6u32).rev() {
            for i in (1..=n).rev() {
                buf[..8].copy_from_slice(&a);
                buf[8..].copy_from_slice(&block[8 * (i - 1)..8 * (i - 1) + 8]);

                // 解密前先把 t XOR 回 A 暫存（與 wrap 的順序相反）。
                let mut t = n as u32 * j + i as u32;
                let mut k = 1;
                while t != 0 {
                    buf[8 - k] ^= t as u8;
                    t >>= 8;
                    k += 1;
                }

                crypt_block(engine, &mut buf)?;
                a.copy_from_slice(&buf[..8]);
                block[8 * (i - 1)..8 * (i - 1) + 8].copy_from_slice(&buf[8..]);
            }
        }
    }

    Ok(a)
}

/// Processes one 16-byte block in place with the already-keyed engine, routing
/// through a scratch buffer to avoid input/output aliasing.
fn crypt_block<E: BlockCipher>(engine: &mut E, block: &mut [u8]) -> Result<(), E::Error> {
    let mut scratch = [0u8; 16];
    engine.process_block(block, &mut scratch)?;
    block.copy_from_slice(&scratch);
    Ok(())
}

/// Constant-time equality of two equal-length slices: XOR each byte pair and
/// accumulate, so the running time does not vary with the number of matching
/// bytes.
pub(crate) fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
