use alloc::vec;
use alloc::vec::Vec;

use tc_macs::{KeyRef, Mac, MacInit};
use tc_zeroize::Zeroize;

use super::counter_field::{CounterField, max_output};
use crate::{Kdf, KdfDoublePipelineParams, KdfError, KdfInit, KdfInitError};

/// The SP 800-108 double-pipeline iteration mode over the MAC `M`, BC's
/// `KdfDoublePipelineIterationBytesGenerator`. Available with the `sp800-108` feature.
///
/// The first pipeline is `A(i) = PRF(Ki, A(i - 1))` with `A(0)` the fixed input, and block `i`
/// is `K(i) = PRF(Ki, A(i) || [i] || fixed input)`, the counter `[i]` left out when the
/// parameters have none. As in BC, each call continues where the last one stopped. With a
/// counter, the output stops at `(2^r - 1)` blocks, the limit of SP 800-108, where BC lets the
/// last counter value wrap to 0. The key lives in the MAC; the fixed input and both pipelines
/// are wiped when replaced and on drop.
pub struct KdfDoublePipeline<M> {
    prf: M,
    fixed_input: Vec<u8>,
    counter: Option<CounterField>,
    a: Vec<u8>,
    k: Vec<u8>,
    generated: u64,
    initialized: bool,
}

impl<M: Mac> KdfDoublePipeline<M> {
    /// A function over `prf`, not yet initialized. Constant time.
    pub fn new(prf: M) -> Self {
        let block = prf.mac_size();
        Self {
            prf,
            fixed_input: Vec::new(),
            counter: None,
            a: vec![0; block],
            k: vec![0; block],
            generated: 0,
            initialized: false,
        }
    }

    fn generate_next(&mut self) -> Result<(), M::Error> {
        if self.generated == 0 {
            self.prf.update(&self.fixed_input)?;
        } else {
            self.prf.update(&self.a)?;
        }
        self.prf.do_final(&mut self.a)?;

        self.prf.update(&self.a)?;
        if let Some(counter) = self.counter {
            let i = (self.generated / self.k.len() as u64 + 1) as u32;
            self.prf.update(&counter.encode(i)[..counter.len()])?;
        }
        self.prf.update(&self.fixed_input)?;
        self.prf.do_final(&mut self.k)?;
        Ok(())
    }
}

impl<M, P, E> KdfInit<P> for KdfDoublePipeline<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = E>,
    E: core::error::Error + 'static,
    P: KdfDoublePipelineParams + ?Sized,
{
    type Error = KdfInitError<E>;

    /// Keys the MAC with `Ki` and copies the fixed input.
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
        self.fixed_input.zeroize();
        self.fixed_input = params.fixed_input().to_vec();
        self.a.fill(0);
        self.k.fill(0);
        self.counter = counter;
        self.generated = 0;
        self.initialized = true;
        Ok(())
    }
}

impl<M> Kdf for KdfDoublePipeline<M>
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

impl<M> Drop for KdfDoublePipeline<M> {
    fn drop(&mut self) {
        self.fixed_input.zeroize();
        self.a.zeroize();
        self.k.zeroize();
    }
}
