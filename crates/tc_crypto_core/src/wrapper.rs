//! Key-wrapping trait, ported from Bouncy Castle's `IWrapper` family.
//!
//! `tc_crypto_core` ships only the *contract*: the parameter and error types are
//! **associated types** supplied by the implementor, so core names no concrete
//! key-encryption-key or error type.
//!
//! A key wrapper encrypts *key material* (rather than arbitrary plaintext) under a
//! key-encryption key, producing a slightly longer blob that carries its own
//! integrity check. Two properties set it apart from a block cipher and shape this
//! trait:
//!
//! * **Its output is owned, not written into a caller slice.** A wrapped blob has
//!   an algorithm-defined, input-dependent length (e.g. `input + 8` bytes for
//!   RFC 3394), and for padded schemes such as RFC 5649 the unwrapped length is
//!   not even known until the integrity check runs. So [`wrap`](Wrapper::wrap) and
//!   [`unwrap`](Wrapper::unwrap) return a freshly allocated `Vec<u8>`, mirroring
//!   bc's `byte[] Wrap(...)`, rather than the `&mut [u8]`-plus-`usize` shape used
//!   by a block cipher's `process_block` operation. This is why the trait lives
//!   behind the crate's `alloc` feature.
//! * **Both directions are fallible.** Unlike a stream cipher's infallible
//!   `reset`, there is no "infallible wrapper" to hand a `Result`-free API:
//!   `wrap` rejects ill-sized input, and `unwrap`'s integrity check *is* the
//!   operation's meaning — a tampered blob or the wrong key must fail. As with
//!   block-cipher contracts, the single trait therefore returns `Result` from all
//!   of its data methods; there is no fallible/infallible split.

use alloc::vec::Vec;

/// A key wrapper (bc `IWrapper`).
///
/// Initialise once with [`init`](Wrapper::init), choosing the direction with its
/// `for_wrapping` flag, then transform key material with [`wrap`](Wrapper::wrap)
/// (protect a key) or [`unwrap`](Wrapper::unwrap) (recover and verify one). A
/// wrapper is built over an underlying block cipher, but exposes only this
/// key-level interface.
pub trait Wrapper {
    /// The parameter accepted by [`init`](Wrapper::init) — bc's
    /// `ICipherParameters`, made concrete per implementor (typically the
    /// key-encryption key, sometimes with an IV).
    ///
    /// A generic associated type so that a *borrowing* parameter (e.g. one that
    /// holds `&'a [u8]` key material) receives a fresh lifetime on every call,
    /// tied only to that call's arguments.
    type Params<'a>;

    /// The failure type; e.g. an invalid key length, ill-sized input, a call in
    /// the wrong direction, or a failed integrity check on unwrap. Use
    /// [`Infallible`](core::convert::Infallible) only if construction and
    /// processing truly cannot fail (no real wrapper qualifies).
    type Error: core::error::Error;

    /// The algorithm name (bc `AlgorithmName`), e.g. `"AES"`.
    fn algorithm_name(&self) -> &str;

    /// Initialises the wrapper for wrapping (`for_wrapping = true`) or unwrapping
    /// (`for_wrapping = false`) with the given parameters (bc `Init`).
    ///
    /// The flag is `for_wrapping`, not `for_encryption`: wrapping is not the same
    /// as encryption — some schemes (e.g. RFC 3394) run the underlying cipher in
    /// the reverse direction to wrap — so the name states the key-level intent.
    ///
    /// The parameters are taken **by reference**: `init` does not consume them, so
    /// one key-encryption key can be built once and handed to any number of `init`
    /// calls (e.g. an `init(true, ..)` to wrap, then an `init(false, ..)` to
    /// unwrap with the same key). Fails if the parameters are unsuitable (wrong
    /// key length, unsupported parameter shape).
    fn init(
        &mut self,
        for_wrapping: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error>;

    /// Wraps `input` (key material) and returns the protected blob (bc `Wrap`).
    ///
    /// The result is a freshly allocated buffer whose length is algorithm-defined
    /// and larger than `input` (e.g. `input.len() + 8` for RFC 3394). Fails if
    /// `input` has an unsuitable length for the algorithm, or the wrapper was not
    /// initialised for wrapping.
    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Unwraps `input` (a blob from [`wrap`](Wrapper::wrap)) and returns the
    /// recovered key material (bc `Unwrap`).
    ///
    /// The embedded integrity check is verified first: a tampered blob, a
    /// truncated blob, or the wrong key yields an error (the operation's whole
    /// point is that a bad blob is rejected rather than returning garbage). On
    /// success the returned buffer is shorter than `input`. Also fails if the
    /// wrapper was not initialised for unwrapping.
    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::fmt;

    // 一個玩具 wrapper,只為驗證 trait 形狀:GAT by-ref param 可重複借用、
    // wrap/unwrap 回擁有式 Vec、unwrap 的完整性檢查是操作語意的一部分。
    // 「包裝」= 每位元組 XOR pad,再附上 1 位元組校驗和(所有明文位元組之和)。

    #[derive(Debug, PartialEq)]
    enum ToyError {
        NotInitialised,
        WrongMode,
        IntegrityCheckFailed,
    }

    impl fmt::Display for ToyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ToyError::NotInitialised => write!(f, "wrapper not initialised"),
                ToyError::WrongMode => write!(f, "wrapper initialised for the other direction"),
                ToyError::IntegrityCheckFailed => write!(f, "integrity check failed"),
            }
        }
    }

    impl core::error::Error for ToyError {}

    struct ToyKey<'a> {
        kek: &'a [u8],
    }

    struct ToyWrapper {
        // None = 尚未 init;Some(true) = 包裝模式;Some(false) = 解包裝模式。
        for_wrapping: Option<bool>,
        pad: u8,
    }

    impl ToyWrapper {
        fn new() -> Self {
            ToyWrapper {
                for_wrapping: None,
                pad: 0,
            }
        }
    }

    impl Wrapper for ToyWrapper {
        type Params<'a> = ToyKey<'a>;
        type Error = ToyError;

        fn algorithm_name(&self) -> &str {
            "Toy"
        }

        fn init(&mut self, for_wrapping: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
            self.pad = params.kek.first().copied().unwrap_or(0);
            self.for_wrapping = Some(for_wrapping);
            Ok(())
        }

        fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
            match self.for_wrapping {
                None => return Err(ToyError::NotInitialised),
                Some(false) => return Err(ToyError::WrongMode),
                Some(true) => {}
            }
            let checksum = input.iter().fold(0u8, |a, &b| a.wrapping_add(b));
            let mut out: Vec<u8> = input.iter().map(|&b| b ^ self.pad).collect();
            out.push(checksum ^ self.pad); // 校驗和同樣遮蓋
            Ok(out)
        }

        fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
            match self.for_wrapping {
                None => return Err(ToyError::NotInitialised),
                Some(true) => return Err(ToyError::WrongMode),
                Some(false) => {}
            }
            if input.is_empty() {
                return Err(ToyError::IntegrityCheckFailed);
            }
            let (body, trailer) = input.split_at(input.len() - 1);
            let plain: Vec<u8> = body.iter().map(|&b| b ^ self.pad).collect();
            let expected = plain.iter().fold(0u8, |a, &b| a.wrapping_add(b));
            let got = trailer[0] ^ self.pad;
            if expected != got {
                return Err(ToyError::IntegrityCheckFailed);
            }
            Ok(plain)
        }
    }

    #[test]
    fn round_trips_and_param_is_reusable_by_reference() {
        let kek = [0x5Au8, 0x01, 0x02];
        let params = ToyKey { kek: &kek };
        let key = [0x11u8, 0x22, 0x33, 0x44];

        let mut w = ToyWrapper::new();

        // by-ref:同一份 params 先 wrap 再 unwrap,兩次 init 都沒消耗它。
        w.init(true, &params).unwrap();
        let wrapped = w.wrap(&key).unwrap();
        assert_eq!(wrapped.len(), key.len() + 1); // 輸出比輸入長

        w.init(false, &params).unwrap();
        let recovered = w.unwrap(&wrapped).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn tampered_blob_fails_integrity_check() {
        let params = ToyKey { kek: &[0x5A] };
        let mut w = ToyWrapper::new();

        w.init(true, &params).unwrap();
        let mut wrapped = w.wrap(&[1u8, 2, 3, 4]).unwrap();
        wrapped[0] ^= 0x01; // 竄改一個 byte

        w.init(false, &params).unwrap();
        assert_eq!(w.unwrap(&wrapped), Err(ToyError::IntegrityCheckFailed));
    }

    #[test]
    fn errors_before_init_and_on_wrong_mode() {
        let params = ToyKey { kek: &[0x5A] };
        let mut w = ToyWrapper::new();

        // 尚未 init。
        assert_eq!(w.wrap(&[1, 2, 3]), Err(ToyError::NotInitialised));

        // init 成 wrapping,卻呼叫 unwrap。
        w.init(true, &params).unwrap();
        let blob = w.wrap(&[1, 2, 3]).unwrap();
        assert_eq!(w.unwrap(&blob), Err(ToyError::WrongMode));

        // 反向:init 成 unwrapping,卻呼叫 wrap。
        w.init(false, &params).unwrap();
        assert_eq!(w.wrap(&[1, 2, 3]), Err(ToyError::WrongMode));

        // 空輸入的 unwrap 視為完整性失敗。
        assert_eq!(w.unwrap(&[]), Err(ToyError::IntegrityCheckFailed));
    }
}
