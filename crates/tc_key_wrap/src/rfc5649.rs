//! RFC 5649 AES Key Wrap with Padding engine, generic over the block cipher.
//!
//! See RFC 5649 (Housley & Dworkin, 2009). This is the shared base for
//! `AesWrapPadEngine` etc., mirroring Bouncy Castle's `Rfc5649WrapEngine`. Unlike
//! RFC 3394 it accepts key material of *any* length: it zero-pads to a multiple
//! of 8 bytes and records the true length in an alternative IV (AIV). The wrap
//! itself reuses the allocation-free RFC 3394 register core
//! ([`crate::rfc3394`]).

use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};

use crate::rfc3394::{fixed_time_eq, unwrap_core_into, wrap_core_in_place};

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
/// with [`new`](Self::new), then use the allocation-free [`KeyWrap`] interface.
pub struct Rfc5649WrapEngine<E: BlockCipher> {
    /// The underlying block cipher engine.
    engine: E,
    /// The AIV prefix in use (chosen at `init`, defaulting to [`DEFAULT_PRE_IV`]).
    pre_iv: [u8; 4],
    /// The key-level operation selected during initialization.
    direction: Option<WrapDirection>,
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
            direction: None,
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
    /// Invalid wrap input length (must fit the RFC 5649 32-bit MLI).
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
            Rfc5649Error::OutputBufferTooShort {
                required,
                available,
            } => f
                .debug_struct("OutputBufferTooShort")
                .field("required", required)
                .field("available", available)
                .finish(),
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
            Rfc5649Error::WrapDataLength => {
                f.write_str("wrap data length must be at least 1 byte and fit the RFC 5649 MLI")
            }
            Rfc5649Error::UnwrapDataLength => {
                f.write_str("unwrap data must be at least 16 bytes and a multiple of 8")
            }
            Rfc5649Error::OutputBufferTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Rfc5649Error::IntegrityCheckFailed => f.write_str("integrity check failed"),
            Rfc5649Error::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl<E: BlockCipher> core::error::Error for Rfc5649Error<E> {}

impl<E: BlockCipherInit> Rfc5649WrapEngine<E> {
    /// Keys the underlying block cipher and records the key-level direction.
    fn initialize(
        &mut self,
        direction: WrapDirection,
        params: &Rfc5649Params<'_, E>,
    ) -> Result<(), Rfc5649Error<E>> {
        // RFC 5649 always uses encryption for wrap and decryption for unwrap.
        let cipher_direction = match direction {
            WrapDirection::Wrap => CipherDirection::Encrypt,
            WrapDirection::Unwrap => CipherDirection::Decrypt,
        };
        self.engine
            .init(cipher_direction, &params.key_params)
            .map_err(Rfc5649Error::BlockCipher)?;
        self.pre_iv = params.pre_iv.unwrap_or(DEFAULT_PRE_IV);
        self.direction = Some(direction);
        Ok(())
    }
}

impl<E: BlockCipher> KeyWrap for Rfc5649WrapEngine<E> {
    type Error = Rfc5649Error<E>;

    fn algorithm_name(&self) -> &str {
        self.engine.algorithm_name()
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len == 0 || u32::try_from(input_len).is_err() {
            return Err(Rfc5649Error::WrapDataLength);
        }

        input_len
            .checked_add(7)
            .map(|length| length & !7)
            .and_then(|padded_len| padded_len.checked_add(8))
            .ok_or(Rfc5649Error::WrapDataLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len < 16 || !input_len.is_multiple_of(8) {
            return Err(Rfc5649Error::UnwrapDataLength);
        }
        Ok(input_len - 8)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(Rfc5649Error::NotForWrapping),
            None => return Err(Rfc5649Error::Uninitialised),
        }

        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc5649Error::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        let block = &mut output[..required];
        block.fill(0);
        block[..4].copy_from_slice(&self.pre_iv);
        block[4..8].copy_from_slice(&(input.len() as u32).to_be_bytes());
        block[8..8 + input.len()].copy_from_slice(input);

        // For a padded payload of eight bytes this is RFC 5649's single-block
        // special case; longer payloads use the RFC 3394 register loop.
        wrap_core_in_place(&mut self.engine, block).map_err(Rfc5649Error::BlockCipher)?;
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Rfc5649Error::NotForUnwrapping),
            None => return Err(Rfc5649Error::Uninitialised),
        }

        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc5649Error::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        let padded = &mut output[..required];
        let aiv = match unwrap_core_into(&mut self.engine, input, padded) {
            Ok(aiv) => aiv,
            Err(error) => {
                padded.fill(0);
                return Err(Rfc5649Error::BlockCipher(error));
            }
        };

        // Run every integrity check even after one fails, matching BC's
        // constant-time-oriented validation structure.
        let mut valid = fixed_time_eq(&aiv[..4], &self.pre_iv);
        let mli = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]) as usize;

        // MLI must lie in (padded.len() - 8, padded.len()].
        let upper = padded.len();
        let lower = upper - 8;
        if mli <= lower || mli > upper {
            valid = false;
        }

        // Padding is zero and contains between zero and seven bytes. Choose a
        // typical length after an invalid MLI so the padding check still runs.
        let expected_zeros = match upper.checked_sub(mli) {
            Some(length) if length < 8 => length,
            _ => {
                valid = false;
                4
            }
        };
        let zeroes = [0_u8; 8];
        let pad = &padded[upper - expected_zeros..];
        if !fixed_time_eq(pad, &zeroes[..expected_zeros]) {
            valid = false;
        }

        if !valid {
            padded.fill(0);
            return Err(Rfc5649Error::IntegrityCheckFailed);
        }

        Ok(mli)
    }
}

impl<E: BlockCipherInit> KeyWrapInit for Rfc5649WrapEngine<E> {
    type Params<'a> = Rfc5649Params<'a, E>;

    fn init(
        &mut self,
        direction: WrapDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.initialize(direction, params)
    }
}
