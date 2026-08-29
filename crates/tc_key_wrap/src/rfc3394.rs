//! RFC 3394 AES Key Wrap engine, generic over the underlying block cipher.
//!
//! See RFC 3394 (Schaad & Housley, 2002). This type is the shared base for
//! concrete wrappers such as `AesWrapEngine`, mirroring Bouncy Castle's
//! `Rfc3394WrapEngine`. The register loop is factored into `wrap_core` /
//! `unwrap_core` so that the RFC 5649 wrapper ([`crate::rfc5649`]) can reuse it.

use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
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
/// [`Wrapper`] trait.
pub struct Rfc3394WrapEngine<E: BlockCipher> {
    /// The underlying block cipher engine.
    engine: E,
    /// Engine direction used when wrapping (= `!use_reverse_direction`); unwrap
    /// uses the opposite.
    wrap_cipher_mode: bool,
    /// The IV in use (chosen at `init`, defaulting to [`DEFAULT_IV`]).
    iv: [u8; 8],
    /// `None` means not yet initialised; `Some(true)` / `Some(false)` selects
    /// wrap / unwrap mode.
    for_wrapping: Option<bool>,
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
            for_wrapping: None,
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
            Rfc3394Error::IntegrityCheckFailed => f.write_str("integrity check failed"),
            Rfc3394Error::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl<E: BlockCipher> core::error::Error for Rfc3394Error<E> {}

impl<E: BlockCipherInit> Wrapper for Rfc3394WrapEngine<E> {
    type Params<'a> = Rfc3394Params<'a, E>;
    type Error = Rfc3394Error<E>;

    fn algorithm_name(&self) -> &str {
        self.engine.algorithm_name()
    }

    fn init(&mut self, for_wrapping: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        // 依方向 key 底層 engine：wrap 用 wrap_cipher_mode，unwrap 取其反。
        // 一次 keying 好，之後 wrap/unwrap 只需 process_block，不必再保存金鑰。
        let for_encryption = if for_wrapping {
            self.wrap_cipher_mode
        } else {
            !self.wrap_cipher_mode
        };
        let direction = if for_encryption {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.engine
            .init(direction, &params.key_params)
            .map_err(Rfc3394Error::BlockCipher)?;

        self.iv = params.iv.unwrap_or(DEFAULT_IV);
        self.for_wrapping = Some(for_wrapping);
        Ok(())
    }

    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self.for_wrapping {
            Some(true) => {}
            Some(false) => return Err(Rfc3394Error::NotForWrapping),
            None => return Err(Rfc3394Error::Uninitialised),
        }
        if input.len() < 8 || !input.len().is_multiple_of(8) {
            return Err(Rfc3394Error::WrapDataLength);
        }
        let iv = self.iv;
        wrap_core(&mut self.engine, &iv, input).map_err(Rfc3394Error::BlockCipher)
    }

    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self.for_wrapping {
            Some(false) => {}
            Some(true) => return Err(Rfc3394Error::NotForUnwrapping),
            None => return Err(Rfc3394Error::Uninitialised),
        }
        if input.len() < 16 || !input.len().is_multiple_of(8) {
            return Err(Rfc3394Error::UnwrapDataLength);
        }
        let (block, a) =
            unwrap_core(&mut self.engine, input).map_err(Rfc3394Error::BlockCipher)?;
        // 以定值時間比較取出的 A 與 IV，校驗失敗即拒絕（避免時序側通道）。
        if !fixed_time_eq(&a, &self.iv) {
            return Err(Rfc3394Error::IntegrityCheckFailed);
        }
        Ok(block)
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
    let n = input.len() / 8;

    // block = IV(8) || input，之後所有運算就地在 block 上進行。
    let mut block = vec![0u8; input.len() + 8];
    block[..8].copy_from_slice(iv);
    block[8..].copy_from_slice(input);

    if n == 1 {
        // 單一資料分組：直接加密 IV||R 這 16 bytes。
        crypt_block(engine, &mut block)?;
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

    Ok(block)
}

/// RFC 3394 unwrap core, **without** the IV check: returns `(data, extracted A)`.
/// The caller validates the extracted A (RFC 3394 compares it to the IV; RFC 5649
/// decodes the AIV and MLI from it). `input` must be at least 16 bytes and a
/// multiple of 8 (the caller checks this).
pub(crate) fn unwrap_core<E: BlockCipher>(
    engine: &mut E,
    input: &[u8],
) -> Result<(Vec<u8>, [u8; 8]), E::Error> {
    // 資料分組數（扣掉開頭的 A 暫存那 8 bytes）。
    let n = input.len() / 8 - 1;

    let mut block = vec![0u8; input.len() - 8];
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

    Ok((block, a))
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
