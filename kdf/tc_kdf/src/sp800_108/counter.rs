use alloc::vec;
use alloc::vec::Vec;

use tc_macs::{KeyRef, Mac, MacInit};
use tc_zeroize::Zeroize;

use super::counter_field::{CounterField, max_output};
use crate::sp800_108::{KdfCounterParams, KdfInitError};
use crate::{Kdf, KdfError, KdfInit};

/// The SP 800-108 counter mode over the MAC `M`, BC's `KdfCounterBytesGenerator`. Available
/// with the `sp800-108` feature.
///
/// Block `i` is `PRF(Ki, prefix || [i] || suffix)` with an `r`-bit counter starting at 1. As in
/// BC, each call continues where the last one stopped. Unlike BC, which lets the last counter
/// value wrap to 0, the output stops at `(2^r - 1)` blocks, the limit of SP 800-108. The key
/// lives in the MAC; the fixed input and the last block are wiped when replaced and on drop.
pub struct KdfCounter<M> {
    prf: M,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    counter: Option<CounterField>,
    k: Vec<u8>,
    generated: u64,
}

impl<M: Mac> KdfCounter<M> {
    /// A function over `prf`, not yet initialized. Constant time.
    pub fn new(prf: M) -> Self {
        let block = prf.mac_size();
        Self {
            prf,
            prefix: Vec::new(),
            suffix: Vec::new(),
            counter: None,
            k: vec![0; block],
            generated: 0,
        }
    }

    fn generate_next(&mut self, counter: CounterField) -> Result<(), M::Error> {
        let i = (self.generated / self.k.len() as u64 + 1) as u32;
        self.prf.update(&self.prefix)?;
        self.prf.update(&counter.encode(i)[..counter.len()])?;
        self.prf.update(&self.suffix)?;
        self.prf.do_final(&mut self.k)?;
        Ok(())
    }
}

impl<M, P, E> KdfInit<P> for KdfCounter<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = E>,
    E: core::error::Error + 'static,
    P: KdfCounterParams + ?Sized,
{
    type Error = KdfInitError<E>;

    /// Keys the MAC with `Ki` and copies the fixed input.
    /// A counter length other than 8, 16, 24 or 32 bits is rejected before anything changes;
    /// when the MAC rejects the key, the function is left uninitialized. Constant time with
    /// respect to `Ki` when the MAC is.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        let bits = params.counter_bits();
        let counter =
            CounterField::from_bits(bits).ok_or(KdfInitError::InvalidCounterLength(bits))?;
        self.counter = None;
        self.prf
            .init(&KeyRef::new(params.ki()))
            .map_err(KdfInitError::Mac)?;
        self.prefix.zeroize();
        self.prefix = params.fixed_input_prefix().to_vec();
        self.suffix.zeroize();
        self.suffix = params.fixed_input_suffix().to_vec();
        self.k.fill(0);
        self.generated = 0;
        self.counter = Some(counter);
        Ok(())
    }
}

impl<M> Kdf for KdfCounter<M>
where
    M: Mac,
    M::Error: 'static,
{
    type Error = KdfError<M::Error>;

    /// Continues the output where the last call stopped. Fails before `init`, or when the
    /// output since `init` would pass `(2^r - 1)` blocks. Constant time with respect to the key
    /// when the MAC is; the output length is public.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let counter = self.counter.ok_or(KdfError::NotInitialised)?;
        let block = self.k.len();
        let length = output.len();
        if length as u64 > max_output(block, Some(counter)) - self.generated {
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
            self.generate_next(counter).map_err(KdfError::Mac)?;
            chunk.copy_from_slice(&self.k[..chunk.len()]);
            self.generated += chunk.len() as u64;
        }
        Ok(length)
    }
}

impl<M> Drop for KdfCounter<M> {
    fn drop(&mut self) {
        self.prefix.zeroize();
        self.suffix.zeroize();
        self.k.zeroize();
    }
}
