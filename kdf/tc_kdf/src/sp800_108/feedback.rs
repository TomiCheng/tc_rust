use alloc::vec;
use alloc::vec::Vec;

use tc_macs::{KeyRef, Mac, MacInit};
use tc_zeroize::Zeroize;

use super::counter_field::{CounterField, max_output};
use crate::sp800_108::{KdfFeedbackParams, KdfInitError};
use crate::{Kdf, KdfError, KdfInit};

/// The SP 800-108 feedback mode over the MAC `M`, BC's `KdfFeedbackBytesGenerator`.
///
/// Block `i` is `K(i) = PRF(Ki, K(i - 1) || [i] || fixed input)` with `K(0)` the IV, and the
/// counter `[i]` left out when the parameters have none. As in BC, each call continues where
/// the last one stopped. With a counter, the output stops at `(2^r - 1)` blocks, the limit of
/// SP 800-108, where BC lets the last counter value wrap to 0. The key lives in the MAC; the
/// IV, fixed input and last block are wiped when replaced and on drop.
pub struct KdfFeedback<M> {
    prf: M,
    iv: Vec<u8>,
    fixed_input: Vec<u8>,
    counter: Option<CounterField>,
    k: Vec<u8>,
    generated: u64,
    initialized: bool,
}

impl<M: Mac> KdfFeedback<M> {
    /// A function over `prf`, not yet initialized. Constant time.
    pub fn new(prf: M) -> Self {
        let block = prf.mac_size();
        Self {
            prf,
            iv: Vec::new(),
            fixed_input: Vec::new(),
            counter: None,
            k: vec![0; block],
            generated: 0,
            initialized: false,
        }
    }

    fn generate_next(&mut self) -> Result<(), M::Error> {
        if self.generated == 0 {
            self.prf.update(&self.iv)?;
        } else {
            self.prf.update(&self.k)?;
        }
        if let Some(counter) = self.counter {
            let i = (self.generated / self.k.len() as u64 + 1) as u32;
            self.prf.update(&counter.encode(i)[..counter.len()])?;
        }
        self.prf.update(&self.fixed_input)?;
        self.prf.do_final(&mut self.k)?;
        Ok(())
    }
}

impl<M, P, E> KdfInit<P> for KdfFeedback<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = E>,
    E: core::error::Error + 'static,
    P: KdfFeedbackParams + ?Sized,
{
    type Error = KdfInitError<E>;

    /// Keys the MAC with `Ki` and copies the IV and fixed input.
    /// A counter length other than 8, 16, 24 or 32 bits is rejected before anything changes;
    /// when the MAC rejects the key, the function is left uninitialized. Constant time with
    /// respect to `Ki` when the MAC is.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        let counter = match params.counter_bits() {
            Some(bits) => Some(
                CounterField::from_bits(bits).ok_or(KdfInitError::InvalidCounterLength(bits))?,
            ),
            None => None,
        };
        self.initialized = false;
        self.prf
            .init(&KeyRef::new(params.ki()))
            .map_err(KdfInitError::Mac)?;
        self.iv.zeroize();
        self.iv = params.iv().to_vec();
        self.fixed_input.zeroize();
        self.fixed_input = params.fixed_input().to_vec();
        self.k.fill(0);
        self.counter = counter;
        self.generated = 0;
        self.initialized = true;
        Ok(())
    }
}

impl<M> Kdf for KdfFeedback<M>
where
    M: Mac,
    M::Error: 'static,
{
    type Error = KdfError<M::Error>;

    /// Continues the output where the last call stopped. Fails before `init`, or, with a
    /// counter, when the output since `init` would pass `(2^r - 1)` blocks. Constant time with
    /// respect to the key when the MAC is; the output length is public.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(KdfError::NotInitialised);
        }
        let block = self.k.len();
        let length = output.len();
        if length as u64 > max_output(block, self.counter) - self.generated {
            return Err(KdfError::OutputTooLong);
        }

        let mut output = output;
        let position = (self.generated % block as u64) as usize;
        if position != 0 {
            let count = (block - position).min(output.len());
            output[..count].copy_from_slice(&self.k[position..position + count]);
            self.generated += count as u64;
            output = &mut output[count..];
        }
        for chunk in output.chunks_mut(block) {
            self.generate_next().map_err(KdfError::Mac)?;
            chunk.copy_from_slice(&self.k[..chunk.len()]);
            self.generated += chunk.len() as u64;
        }
        Ok(length)
    }
}

impl<M> Drop for KdfFeedback<M> {
    fn drop(&mut self) {
        self.iv.zeroize();
        self.fixed_input.zeroize();
        self.k.zeroize();
    }
}
