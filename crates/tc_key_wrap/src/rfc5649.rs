//! RFC 5649 AES Key Wrap with Padding engine, generic over the block cipher.
//!
//! See RFC 5649 (Housley & Dworkin, 2009). This is the shared base for
//! `AesWrapPadEngine` etc., mirroring Bouncy Castle's `Rfc5649WrapEngine`. Unlike
//! RFC 3394 it accepts key material of *any* length: it zero-pads to a multiple
//! of 8 bytes and records the true length in an alternative IV (AIV). The wrap
//! itself reuses the RFC 3394 register core ([`crate::rfc3394`]).

use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_crypto_core::Wrapper;

use crate::rfc3394::{fixed_time_eq, unwrap_core, wrap_core};

/// The high 4 bytes of the RFC 5649 AIV (`A6 59 59 A6`); the low 4 bytes carry
/// the message length indicator (MLI).
const DEFAULT_PRE_IV: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];

/// Parameters for an RFC 5649 wrapper: the underlying engine's key parameters
/// plus an optional custom 4-byte AIV prefix.
pub struct Rfc5649Params<'a, E: BlockCipherInit> {
    /// The underlying block cipher's key parameters (e.g. `AesParams`).
    key_params: <E as BlockCipherInit>::Params<'a>,
    /// A custom AIV prefix; `None` uses [`DEFAULT_PRE_IV`].
    pre_iv: Option<[u8; 4]>,
}

impl<'a, E: BlockCipherInit> Rfc5649Params<'a, E> {
    /// Builds parameters from the engine's key parameters, using the default AIV
    /// prefix.
    pub fn new(key_params: <E as BlockCipherInit>::Params<'a>) -> Self {
        Self {
            key_params,
            pre_iv: None,
        }
    }

    /// Builds parameters from the engine's key parameters and a custom 4-byte AIV
    /// prefix.
    pub fn with_iv(key_params: <E as BlockCipherInit>::Params<'a>, pre_iv: [u8; 4]) -> Self {
        Self {
            key_params,
            pre_iv: Some(pre_iv),
        }
    }
}

/// RFC 5649 AES Key Wrap with Padding, generic over the underlying block cipher.
///
/// Mirrors bc's `Rfc5649WrapEngine`. Inject the underlying engine (128-bit block)
/// with [`new`](Self::new), then wrap / unwrap through the [`Wrapper`] trait.
pub struct Rfc5649WrapEngine<E: BlockCipher> {
    /// The underlying block cipher engine.
    engine: E,
    /// The AIV prefix in use (chosen at `init`, defaulting to [`DEFAULT_PRE_IV`]).
    pre_iv: [u8; 4],
    /// `None` means not yet initialised; `Some(true)` / `Some(false)` selects
    /// wrap / unwrap mode.
    for_wrapping: Option<bool>,
}

impl<E: BlockCipher> Rfc5649WrapEngine<E> {
    /// Builds a wrapper over the given engine.
    pub fn new(engine: E) -> Self {
        assert_eq!(
            engine.block_size(),
            16,
            "RFC 5649 requires a 128-bit (16-byte) block, but {} has a {}-byte block",
            engine.algorithm_name(),
            engine.block_size(),
        );

        Self {
            engine,
            pre_iv: DEFAULT_PRE_IV,
            for_wrapping: None,
        }
    }
}

/// Builds the wrapper over a freshly constructed underlying engine
/// (`E::default()`), so the concrete aliases can be created with no arguments.
impl<E: BlockCipher + Default> Default for Rfc5649WrapEngine<E> {
    fn default() -> Self {
        Self::new(E::default())
    }
}

/// Error type for the RFC 5649 wrapper.
pub enum Rfc5649Error<E: BlockCipher> {
    /// wrap / unwrap called before `init`.
    Uninitialised,
    /// Initialised for unwrapping, but `wrap` was called.
    NotForWrapping,
    /// Initialised for wrapping, but `unwrap` was called.
    NotForUnwrapping,
    /// Empty wrap input (RFC 5649 needs at least one byte of key material).
    WrapDataLength,
    /// Invalid unwrap input length (must be at least 16 and a multiple of 8).
    UnwrapDataLength,
    /// Integrity check failed on unwrap (bad AIV, length, or padding).
    IntegrityCheckFailed,
    /// Error reported by the underlying block cipher engine.
    BlockCipher(E::Error),
}

// Debug 手寫，理由同 rfc3394：需要 `E::Error: Debug` 而非 `E: Debug`。
impl<E: BlockCipher> core::fmt::Debug for Rfc5649Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Rfc5649Error::Uninitialised => f.write_str("Uninitialised"),
            Rfc5649Error::NotForWrapping => f.write_str("NotForWrapping"),
            Rfc5649Error::NotForUnwrapping => f.write_str("NotForUnwrapping"),
            Rfc5649Error::WrapDataLength => f.write_str("WrapDataLength"),
            Rfc5649Error::UnwrapDataLength => f.write_str("UnwrapDataLength"),
            Rfc5649Error::IntegrityCheckFailed => f.write_str("IntegrityCheckFailed"),
            Rfc5649Error::BlockCipher(e) => f.debug_tuple("BlockCipher").field(e).finish(),
        }
    }
}

impl<E: BlockCipher> core::fmt::Display for Rfc5649Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Rfc5649Error::Uninitialised => f.write_str("key wrapper not initialised"),
            Rfc5649Error::NotForWrapping => f.write_str("wrapper not set for wrapping"),
            Rfc5649Error::NotForUnwrapping => f.write_str("wrapper not set for unwrapping"),
            Rfc5649Error::WrapDataLength => f.write_str("wrap data must be at least 1 byte"),
            Rfc5649Error::UnwrapDataLength => {
                f.write_str("unwrap data must be at least 16 bytes and a multiple of 8")
            }
            Rfc5649Error::IntegrityCheckFailed => f.write_str("integrity check failed"),
            Rfc5649Error::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl<E: BlockCipher> core::error::Error for Rfc5649Error<E> {}

impl<E: BlockCipherInit> Wrapper for Rfc5649WrapEngine<E> {
    type Params<'a> = Rfc5649Params<'a, E>;
    type Error = Rfc5649Error<E>;

    fn algorithm_name(&self) -> &str {
        self.engine.algorithm_name()
    }

    fn init(&mut self, for_wrapping: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        // RFC 5649 一律 wrap=加密、unwrap=解密（無 reverse 選項）。
        let direction = if for_wrapping {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.engine
            .init(direction, &params.key_params)
            .map_err(Rfc5649Error::BlockCipher)?;
        self.pre_iv = params.pre_iv.unwrap_or(DEFAULT_PRE_IV);
        self.for_wrapping = Some(for_wrapping);
        Ok(())
    }

    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self.for_wrapping {
            Some(true) => {}
            Some(false) => return Err(Rfc5649Error::NotForWrapping),
            None => return Err(Rfc5649Error::Uninitialised),
        }
        if input.is_empty() {
            return Err(Rfc5649Error::WrapDataLength);
        }

        // AIV = pre_iv(4) || MLI(4, big-endian = 原始金鑰長度)。
        let mut aiv = [0u8; 8];
        aiv[..4].copy_from_slice(&self.pre_iv);
        aiv[4..].copy_from_slice(&(input.len() as u32).to_be_bytes());

        // 補零到 8 的倍數。
        let num_zeros = (8 - input.len() % 8) % 8;
        let mut padded = vec![0u8; input.len() + num_zeros];
        padded[..input.len()].copy_from_slice(input);

        // wrap_core 的 n==1 分支剛好等於 RFC 5649 的單塊特例，兩種長度共用。
        wrap_core(&mut self.engine, &aiv, &padded).map_err(Rfc5649Error::BlockCipher)
    }

    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self.for_wrapping {
            Some(false) => {}
            Some(true) => return Err(Rfc5649Error::NotForUnwrapping),
            None => return Err(Rfc5649Error::Uninitialised),
        }
        if input.len() < 16 || !input.len().is_multiple_of(8) {
            return Err(Rfc5649Error::UnwrapDataLength);
        }

        let (padded, aiv) =
            unwrap_core(&mut self.engine, input).map_err(Rfc5649Error::BlockCipher)?;

        // 即使某項失敗仍把每項檢查跑完，避免時序側通道（照 bc）。
        let mut valid = fixed_time_eq(&aiv[..4], &self.pre_iv);
        let mli = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]) as usize;

        // MLI 應落在 (padded.len() - 8, padded.len()]。
        let upper = padded.len();
        let lower = upper - 8;
        if mli <= lower || mli > upper {
            valid = false;
        }

        // padding 應是 upper - mli 個零，且該數量落在 [0, 8)。
        let mut expected_zeros = upper as i64 - mli as i64;
        if !(0..8).contains(&expected_zeros) {
            valid = false;
            expected_zeros = 4; // 挑一個「典型」量以維持定值時間比較
        }
        let expected_zeros = expected_zeros as usize;
        let zeros = vec![0u8; expected_zeros];
        let pad = &padded[padded.len() - expected_zeros..];
        if !fixed_time_eq(pad, &zeros) {
            valid = false;
        }

        if !valid {
            return Err(Rfc5649Error::IntegrityCheckFailed);
        }
        Ok(padded[..mli].to_vec())
    }
}
