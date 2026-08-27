//! Extendable-output function traits, ported from Bouncy Castle's `IXof`.
//!
//! Like the digest API, this module provides a fallible base trait and an
//! infallible convenience trait:
//!
//! - [`TryXof`] extends [`TryDigest`] with fallible, variable-length output.
//! - [`Xof`] is the `Error = Infallible` convenience API and is blanket
//!   implemented for pure-software XOFs.

use core::convert::Infallible;

use crate::{Digest, TryDigest};

/// A streaming extendable-output function whose operations may fail.
///
/// Input is absorbed through [`TryDigest::try_update`]. The first call to
/// [`try_output`](TryXof::try_output) finalizes absorption and starts squeezing;
/// subsequent calls continue the same output stream without resetting it.
/// [`try_output_final`](TryXof::try_output_final) produces the requested output
/// and then resets the XOF for a new message.
///
/// Because this trait extends [`TryDigest`], implementations also provide a
/// fixed default output through [`TryDigest::try_do_final`], whose length is
/// [`TryDigest::digest_size`].
///
/// Updating after squeezing has started is invalid. Call
/// [`TryDigest::try_reset`] before absorbing another message.
pub trait TryXof: TryDigest {
    /// Starts or continues squeezing output without resetting the XOF.
    ///
    /// The method fills `output` and returns `output.len()`. Multiple calls are
    /// contiguous: two calls requesting `a` and `b` bytes produce the same byte
    /// sequence as one call requesting `a + b` bytes.
    ///
    /// Even an empty output slice starts the squeezing phase.
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Finalizes absorption, fills `output`, and resets the XOF.
    ///
    /// The method returns `output.len()`. Unlike
    /// [`try_output`](TryXof::try_output), the next operation may immediately
    /// absorb a new message.
    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// An extendable-output function that cannot fail.
///
/// This is the infallible counterpart of [`TryXof`]. Implementors should only
/// implement [`TryDigest`] and [`TryXof`] with `Error = Infallible`; the blanket
/// implementation below supplies both [`Digest`] and `Xof` convenience APIs.
pub trait Xof: TryXof<Error = Infallible> + Digest {
    /// Starts or continues squeezing and fills `output` without resetting.
    fn output(&mut self, output: &mut [u8]) -> usize;

    /// Fills `output`, then resets the XOF for a new message.
    fn output_final(&mut self, output: &mut [u8]) -> usize;
}

impl<T> Xof for T
where
    T: TryXof<Error = Infallible> + Digest + ?Sized,
{
    #[inline]
    fn output(&mut self, output: &mut [u8]) -> usize {
        match self.try_output(output) {
            Ok(written) => written,
        }
    }

    #[inline]
    fn output_final(&mut self, output: &mut [u8]) -> usize {
        match self.try_output_final(output) {
            Ok(written) => written,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Toy XOF used only to verify trait wiring and stream/reset semantics.
    #[derive(Default)]
    struct CounterXof {
        sum: u8,
        next: u8,
        squeezing: bool,
    }

    impl TryDigest for CounterXof {
        type Error = Infallible;

        fn algorithm_name(&self) -> &str {
            "COUNTER-XOF"
        }

        fn digest_size(&self) -> usize {
            1
        }

        fn byte_length(&self) -> usize {
            1
        }

        fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            assert!(!self.squeezing, "cannot absorb after squeezing starts");
            for &byte in input {
                self.sum = self.sum.wrapping_add(byte);
            }
            Ok(())
        }

        fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            self.try_output_final(&mut output[..1])
        }

        fn try_reset(&mut self) -> Result<(), Self::Error> {
            self.sum = 0;
            self.next = 0;
            self.squeezing = false;
            Ok(())
        }
    }

    impl TryXof for CounterXof {
        fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            if !self.squeezing {
                self.next = self.sum;
                self.squeezing = true;
            }

            for byte in &mut *output {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(output.len())
        }

        fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            let written = self.try_output(output)?;
            self.try_reset()?;
            Ok(written)
        }
    }

    #[test]
    fn infallible_impl_gets_xof_for_free() {
        let mut xof = CounterXof::default();
        xof.update(&[1, 2]);

        let mut first = [0u8; 2];
        let mut second = [0u8; 3];
        assert_eq!(xof.output(&mut first), 2);
        assert_eq!(xof.output(&mut second), 3);
        assert_eq!(first, [3, 4]);
        assert_eq!(second, [5, 6, 7]);
    }

    #[test]
    fn output_final_leaves_xof_reset() {
        let mut xof = CounterXof::default();
        xof.update(&[4, 5]);

        let mut output = [0u8; 3];
        assert_eq!(xof.output_final(&mut output), 3);
        assert_eq!(output, [9, 10, 11]);

        xof.update(&[20]);
        xof.output_final(&mut output);
        assert_eq!(output, [20, 21, 22]);
    }

    #[test]
    fn digest_do_final_uses_default_length_and_resets() {
        let mut xof = CounterXof::default();
        xof.update(&[7, 8]);

        let mut output = [0u8; 1];
        assert_eq!(xof.do_final(&mut output), 1);
        assert_eq!(output, [15]);

        xof.update(&[2]);
        xof.do_final(&mut output);
        assert_eq!(output, [2]);
    }

    #[test]
    fn empty_output_starts_squeezing() {
        let mut xof = CounterXof::default();
        xof.update(&[42]);
        assert_eq!(xof.output(&mut []), 0);

        let mut output = [0u8; 2];
        xof.output(&mut output);
        assert_eq!(output, [42, 43]);
    }
}
