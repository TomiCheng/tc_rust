use alloc::vec;
use alloc::vec::Vec;

use tc_digest::Digest;
use tc_zeroize::Zeroizing;

use crate::state::PbeState;
use crate::{PbeError, PbeGenerator, PbeGeneratorInit, PbeParams};

/// PKCS#5 scheme 1, PBKDF1 of RFC 8018, BC's `Pkcs5S1ParametersGenerator`: `T1 = H(P || S)`,
/// then `Ti = H(T(i - 1))` up to the iteration count, and the key, IV or MAC key are cut from
/// the front of the last `T`, so together they take at most one digest.
///
/// The password and salt copied at `init` are wiped when replaced and on drop, and so is every
/// `T`.
pub struct Pkcs5S1<D> {
    digest: D,
    state: Option<PbeState>,
}

impl<D> Pkcs5S1<D> {
    /// A generator over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            digest,
            state: None,
        }
    }
}

impl<D: Digest> Pkcs5S1<D> {
    /// The last `T`, `len` bytes of it checked to fit.
    fn derive(&mut self, len: usize) -> Result<Zeroizing<Vec<u8>>, PbeError> {
        let state = self.state.as_ref().ok_or(PbeError::NotInitialised)?;
        let digest_size = self.digest.digest_size();
        if len > digest_size {
            return Err(PbeError::OutputTooLong);
        }
        let mut t = Zeroizing::new(vec![0; digest_size]);
        self.digest.reset();
        self.digest.update(&state.password);
        self.digest.update(&state.salt);
        self.digest.do_final(&mut t);
        for _ in 1..state.iteration_count {
            self.digest.update(&t);
            self.digest.do_final(&mut t);
        }
        Ok(t)
    }
}

impl<D, P: PbeParams + ?Sized> PbeGeneratorInit<P> for Pkcs5S1<D> {
    type Error = PbeError;

    /// Copies the password and salt. An iteration count of 0, which BC runs as 1, is refused
    /// before anything changes. Constant time with respect to the password and salt.
    fn init(&mut self, params: &P) -> Result<(), PbeError> {
        self.state = Some(PbeState::copy(params)?);
        Ok(())
    }
}

impl<D: Digest> PbeGenerator for Pkcs5S1<D> {
    type Error = PbeError;

    /// Fills `key` from the front of the last `T`. Fails before `init`, or when `key` is longer
    /// than the digest. Constant time with respect to the password and salt when the digest
    /// is; the iteration count and lengths are public.
    fn derive_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        let t = self.derive(key.len())?;
        key.copy_from_slice(&t[..key.len()]);
        Ok(())
    }

    /// Fills `key` and then `iv` from the front of the last `T`. Fails before `init`, or when
    /// they are longer together than the digest. Constant time with respect to the password
    /// and salt when the digest is; the iteration count and lengths are public.
    fn derive_key_and_iv(&mut self, key: &mut [u8], iv: &mut [u8]) -> Result<(), PbeError> {
        let t = self.derive(key.len() + iv.len())?;
        let (key_bytes, rest) = t.split_at(key.len());
        key.copy_from_slice(key_bytes);
        iv.copy_from_slice(&rest[..iv.len()]);
        Ok(())
    }

    /// The same bytes as [`derive_key`](Self::derive_key), as in BC. Constant time with
    /// respect to the password and salt when the digest is; the iteration count and lengths
    /// are public.
    fn derive_mac_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        self.derive_key(key)
    }
}
