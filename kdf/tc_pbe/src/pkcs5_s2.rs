use alloc::vec;
use alloc::vec::Vec;

use tc_digest::Digest;
use tc_macs::{Hmac, KeyRef, Mac, MacInit};
use tc_zeroize::Zeroizing;

use crate::state::PbeState;
use crate::{PbeError, PbeGenerator, PbeGeneratorInit, PbeParams};

/// PKCS#5 scheme 2, PBKDF2 of RFC 8018 over HMAC with the digest `D`, BC's
/// `Pkcs5S2ParametersGenerator`.
///
/// Block `i` is `U1 xor U2 xor ... xor Uc`, with `U1 = HMAC(P, S || INT(i))` and
/// `Uj = HMAC(P, U(j - 1))`. The key and IV are taken in turn from one output, so together they
/// may run to `(2^32 - 1)` blocks. The MAC key is the same bytes as the cipher key, as in BC.
///
/// The password and salt copied at `init` are wiped when replaced and on drop, and so is every
/// block; the HMAC wipes its own keyed pads. scrypt passes a secret as the salt.
pub struct Pkcs5S2<D> {
    hmac: Hmac<D>,
    state: Option<PbeState>,
}

impl<D: Digest> Pkcs5S2<D> {
    /// A generator over `digest`, not yet initialized. Constant time.
    ///
    /// # Panics
    ///
    /// As [`Hmac::new`]: when the digest's block is shorter than 16 bytes or than its output.
    pub fn new(digest: D) -> Self {
        Self {
            hmac: Hmac::new(digest),
            state: None,
        }
    }

    /// The first `len` bytes of the PBKDF2 output.
    fn derive(&mut self, len: usize) -> Result<Zeroizing<Vec<u8>>, PbeError> {
        let state = self.state.as_ref().ok_or(PbeError::NotInitialised)?;
        let block_len = self.hmac.mac_size();
        if len as u64 > u64::from(u32::MAX) * block_len as u64 {
            return Err(PbeError::OutputTooLong);
        }
        let Ok(()) = self.hmac.init(&KeyRef::new(&state.password));

        let mut output = Zeroizing::new(vec![0; len]);
        let mut u = Zeroizing::new(vec![0; block_len]);
        let mut t = Zeroizing::new(vec![0; block_len]);
        for (index, block) in output.chunks_mut(block_len).enumerate() {
            let i = index as u32 + 1;
            self.hmac.update(&state.salt).map_err(PbeError::Mac)?;
            self.hmac.update(&i.to_be_bytes()).map_err(PbeError::Mac)?;
            self.hmac.do_final(&mut u).map_err(PbeError::Mac)?;
            t.copy_from_slice(&u);
            for _ in 1..state.iteration_count {
                self.hmac.update(&u).map_err(PbeError::Mac)?;
                self.hmac.do_final(&mut u).map_err(PbeError::Mac)?;
                for (t, u) in t.iter_mut().zip(u.iter()) {
                    *t ^= u;
                }
            }
            block.copy_from_slice(&t[..block.len()]);
        }
        Ok(output)
    }
}

impl<D, P: PbeParams + ?Sized> PbeGeneratorInit<P> for Pkcs5S2<D> {
    type Error = PbeError;

    /// Copies the password and salt. An iteration count of 0 is refused before anything
    /// changes, as BC refuses it when deriving. Constant time with respect to the password and
    /// salt.
    fn init(&mut self, params: &P) -> Result<(), PbeError> {
        self.state = Some(PbeState::copy(params)?);
        Ok(())
    }
}

impl<D: Digest> PbeGenerator for Pkcs5S2<D> {
    type Error = PbeError;

    /// Fills `key` with the start of the output. Fails before `init`, or past `(2^32 - 1)`
    /// blocks. Constant time with respect to the password and salt when the digest is; the
    /// iteration count and lengths are public.
    fn derive_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        let output = self.derive(key.len())?;
        key.copy_from_slice(&output);
        Ok(())
    }

    /// Fills `key` and then `iv` from one output. Fails before `init`, or past `(2^32 - 1)`
    /// blocks together. Constant time with respect to the password and salt when the digest
    /// is; the iteration count and lengths are public.
    fn derive_key_and_iv(&mut self, key: &mut [u8], iv: &mut [u8]) -> Result<(), PbeError> {
        let output = self.derive(key.len() + iv.len())?;
        let (key_bytes, iv_bytes) = output.split_at(key.len());
        key.copy_from_slice(key_bytes);
        iv.copy_from_slice(iv_bytes);
        Ok(())
    }

    /// The same bytes as [`derive_key`](Self::derive_key), as in BC. Constant time with
    /// respect to the password and salt when the digest is; the iteration count and lengths
    /// are public.
    fn derive_mac_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        self.derive_key(key)
    }
}
