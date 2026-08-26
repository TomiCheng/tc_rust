//! Message-digest traits, ported from Bouncy Castle's `IDigest`.
//!
//! Structured as a fallible base trait plus an infallible convenience trait,
//! mirroring `rand_core`'s [`TryRng`] / [`Rng`] pair:
//!
//! - [`TryDigest`] is the base: its data-consuming methods return
//!   `Result<_, Self::Error>`, for digests backed by something that can fail
//!   (hardware accelerators, HSMs, remote services).
//! - [`Digest`] is the infallible subtrait — `TryDigest<Error = Infallible>` —
//!   giving pure-software digests (SHA-512 and friends, which never fail) a clean
//!   `Result`-free API. It is blanket-implemented, so implementors only ever write
//!   a [`TryDigest`] impl.
//!
//! [`TryRng`]: https://docs.rs/rand_core/latest/rand_core/trait.TryRng.html
//! [`Rng`]: https://docs.rs/rand_core/latest/rand_core/trait.Rng.html

use core::convert::Infallible;

/// A streaming message digest whose operations may fail.
///
/// The fallible base trait (the Rust equivalent of Bouncy Castle's `IDigest`,
/// generalized to a fallible backend): feed data in with
/// [`try_update`](TryDigest::try_update), then call
/// [`try_do_final`](TryDigest::try_do_final) to produce the digest, which leaves
/// the digest reset and ready to reuse.
///
/// Pure-software hashes never fail; they set `Error = Infallible` and thereby also
/// get the infallible [`Digest`] API for free. The `Error = Infallible` case is
/// exactly the parallel of an infallible RNG in `rand_core`.
///
/// The three size/name accessors never fail, so they are plain (non-`Result`)
/// getters even here; [`Digest`] inherits them unchanged.
pub trait TryDigest {
    /// The failure type; use [`Infallible`] for digests that cannot fail.
    type Error: core::error::Error;

    /// The algorithm name (bc `AlgorithmName`), e.g. `"SHA-512"`.
    fn algorithm_name(&self) -> &str;

    /// The size, in bytes, of the digest this function produces
    /// (bc `GetDigestSize`).
    fn digest_size(&self) -> usize;

    /// The size, in bytes, of the internal block buffer (bc `GetByteLength`);
    /// e.g. 128 for the SHA-512 family.
    fn byte_length(&self) -> usize;

    /// Feeds a block of bytes into the digest (bc `BlockUpdate`).
    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Feeds a single byte into the digest (bc `Update`).
    ///
    /// Provided by default via [`try_update`](TryDigest::try_update); override for
    /// a faster single-byte path.
    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.try_update(&[input])
    }

    /// Finalizes the digest, writing the result into the start of `output` and
    /// returning the number of bytes written (always [`digest_size`]); the digest
    /// is left **reset** (bc `DoFinal`).
    ///
    /// `output` must be at least [`digest_size`](TryDigest::digest_size) long.
    ///
    /// [`digest_size`]: TryDigest::digest_size
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Resets the digest back to its initial state (bc `Reset`).
    fn try_reset(&mut self) -> Result<(), Self::Error>;
}

/// A streaming message digest that cannot fail (the common case).
///
/// The infallible counterpart of [`TryDigest`], analogous to `rand_core`'s
/// [`Rng`] over [`TryRng`]. It adds `Result`-free versions of the data-consuming
/// operations; the name/size accessors are inherited from [`TryDigest`].
///
/// You never implement this directly: any `TryDigest<Error = Infallible>` gets it
/// through the blanket impl below.
///
/// [`TryRng`]: https://docs.rs/rand_core/latest/rand_core/trait.TryRng.html
/// [`Rng`]: https://docs.rs/rand_core/latest/rand_core/trait.Rng.html
pub trait Digest: TryDigest<Error = Infallible> {
    /// Feeds a block of bytes into the digest (bc `BlockUpdate`).
    fn update(&mut self, input: &[u8]);

    /// Feeds a single byte into the digest (bc `Update`).
    fn update_byte(&mut self, input: u8);

    /// Finalizes the digest into the start of `output`, returning the number of
    /// bytes written (always [`digest_size`]); leaves the digest **reset**.
    ///
    /// [`digest_size`]: TryDigest::digest_size
    fn do_final(&mut self, output: &mut [u8]) -> usize;

    /// Resets the digest back to its initial state (bc `Reset`).
    fn reset(&mut self);
}

impl<D> Digest for D
where
    D: TryDigest<Error = Infallible> + ?Sized,
{
    #[inline]
    fn update(&mut self, input: &[u8]) {
        // Err(Infallible) is uninhabited, so this match is exhaustive without an
        // Err arm — the same trick rand_core uses for `Rng` over `TryRng`.
        match self.try_update(input) {
            Ok(()) => (),
        }
    }

    #[inline]
    fn update_byte(&mut self, input: u8) {
        match self.try_update_byte(input) {
            Ok(()) => (),
        }
    }

    #[inline]
    fn do_final(&mut self, output: &mut [u8]) -> usize {
        match self.try_do_final(output) {
            Ok(n) => n,
        }
    }

    #[inline]
    fn reset(&mut self) {
        match self.try_reset() {
            Ok(()) => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 玩具 digest：只把吃進的位元組加總取低 8 bit，用來驗 trait 接線,非真雜湊。
    #[derive(Default)]
    struct SumDigest {
        sum: u8,
    }

    impl TryDigest for SumDigest {
        type Error = Infallible; // 純計算,永不失敗 → 自動獲得 Digest

        fn algorithm_name(&self) -> &str {
            "SUM-8"
        }
        fn digest_size(&self) -> usize {
            1
        }
        fn byte_length(&self) -> usize {
            1
        }
        fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            for &b in input {
                self.sum = self.sum.wrapping_add(b);
            }
            Ok(())
        }
        fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            output[0] = self.sum;
            self.try_reset()?;
            Ok(1)
        }
        fn try_reset(&mut self) -> Result<(), Self::Error> {
            self.sum = 0;
            Ok(())
        }
    }

    #[test]
    fn infallible_impl_gets_digest_for_free() {
        // 只實作了 TryDigest<Error = Infallible>,卻能直接呼叫 Digest 的免-Result 方法。
        let mut d = SumDigest::default();
        d.update(&[1, 2, 3]);
        d.update_byte(4);
        let mut out = [0u8; 1];
        let n = d.do_final(&mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0], 10); // 1+2+3+4
        // getter 由 TryDigest 繼承而來。
        assert_eq!(d.algorithm_name(), "SUM-8");
        assert_eq!(d.digest_size(), 1);
    }

    #[test]
    fn do_final_leaves_digest_reset() {
        let mut d = SumDigest::default();
        d.update(&[5, 5]);
        let mut out = [0u8; 1];
        d.do_final(&mut out);
        assert_eq!(out[0], 10);
        // 上一輪 final 後應歸零,新訊息從頭算。
        d.update(&[7]);
        d.do_final(&mut out);
        assert_eq!(out[0], 7);
    }
}
