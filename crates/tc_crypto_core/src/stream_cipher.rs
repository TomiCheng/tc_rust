//! Stream-cipher trait, ported from Bouncy Castle's `IStreamCipher`.
//!
//! Like [`BlockCipher`](crate::BlockCipher), `tc_crypto_core` ships only the
//! *contract*: the parameter and error types are **associated types** supplied by
//! the implementor, so core names no concrete key or error type.
//!
//! A stream cipher differs from a block cipher in two ways that shape this trait:
//!
//! * **It carries running keystream state.** Each byte produced advances an
//!   internal position, so [`return_byte`](StreamCipher::return_byte) and
//!   [`process_bytes`](StreamCipher::process_bytes) take `&mut self` — unlike a
//!   block cipher's `process_block`, which is a stateless keyed permutation.
//! * **It has no block size.** It consumes an arbitrary-length byte stream, so
//!   there is no `block_size` accessor (bc's `IStreamCipher` has none either).
//!
//! The fallibility of each method follows the operation's meaning rather than its
//! receiver: producing keystream is a bounded operation (several ciphers cap how
//! much keystream a key may generate), so the data methods return `Result`;
//! [`reset`](StreamCipher::reset) merely restores the post-init state — a closed
//! operation over owned state that cannot fail — so it returns `()`, mirroring
//! bc's `void Reset`.

/// A symmetric-key stream cipher (bc `IStreamCipher`).
///
/// Initialise once with [`init`](StreamCipher::init), then combine keystream with
/// data via [`process_bytes`](StreamCipher::process_bytes) (bulk) or
/// [`return_byte`](StreamCipher::return_byte) (one byte). Both advance the
/// keystream, so processing is order-dependent; [`reset`](StreamCipher::reset)
/// rewinds to the state just after `init`.
pub trait StreamCipher {
    /// The parameter accepted by [`init`](StreamCipher::init) — bc's
    /// `ICipherParameters`, made concrete per implementor.
    ///
    /// A generic associated type so that a *borrowing* parameter (e.g. one that
    /// holds `&'a [u8]` key material) receives a fresh lifetime on every call,
    /// tied only to that call's arguments.
    type Params<'a>;

    /// The failure type; e.g. an invalid key, an output buffer too short, or an
    /// exhausted keystream. Use [`Infallible`](core::convert::Infallible) only if
    /// initialisation and processing truly cannot fail.
    type Error: core::error::Error;

    /// The algorithm name (bc `AlgorithmName`), e.g. `"Salsa20"`.
    fn algorithm_name(&self) -> &str;

    /// Initialises the cipher for encryption (`for_encryption = true`) or
    /// decryption (`for_encryption = false`) with the given parameters
    /// (bc `Init`).
    ///
    /// For most stream ciphers encryption and decryption are the same operation
    /// (XOR with keystream), but the flag is kept for parity with `IStreamCipher`
    /// and for ciphers that distinguish the two.
    ///
    /// The parameters are taken **by reference**: `init` does not consume them, so
    /// one parameter value can be built once and handed to any number of `init`
    /// calls. Fails if the parameters are unsuitable (e.g. wrong key or nonce
    /// length).
    fn init(
        &mut self,
        for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error>;

    /// Encrypts/decrypts a single byte, advancing the keystream (bc `ReturnByte`).
    ///
    /// Fails for the same runtime reasons as
    /// [`process_bytes`](StreamCipher::process_bytes) — chiefly an exhausted
    /// keystream on ciphers that bound it, or a call before [`init`].
    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error>;

    /// Processes `input` into `output`, returning the number of bytes written
    /// (bc `ProcessBytes`).
    ///
    /// A stream cipher writes exactly one output byte per input byte, so `output`
    /// must be at least as long as `input` and the returned count equals
    /// `input.len()`. Fails if `output` is too short, the cipher was never
    /// initialised, or the keystream is exhausted.
    fn process_bytes(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// Resets the cipher to the state it had immediately after the last
    /// [`init`](StreamCipher::init) (bc `Reset`).
    ///
    /// This is a closed operation over the cipher's own state and so is
    /// infallible; after it the keystream restarts from the beginning.
    fn reset(&mut self);
}
