use alloc::vec;
use alloc::vec::Vec;

use tc_digest::Digest;
use tc_zeroize::Zeroizing;

use crate::state::PbeState;
use crate::{PbeError, PbeGenerator, PbeGeneratorInit, PbeParams};

/// OpenSSL's `EVP_BytesToKey` with one iteration, BC's `OpenSslPbeParametersGenerator`:
/// `D1 = H(P || S)` and `Di = H(D(i - 1) || P || S)`, joined until the key and IV are covered.
///
/// As in BC, the iteration count is ignored and taken as 1, which is what `openssl enc` uses
/// without `-iter`; BC's default digest is MD5. The key and IV are taken in turn from one output,
/// and the MAC key is the same bytes as the cipher key. The password and salt copied at `init` are
/// wiped when replaced and on drop, and so is every `D`.
pub struct OpenSslPbe<D> {
    digest: D,
    state: Option<PbeState>,
}

impl<D> OpenSslPbe<D> {
    /// A generator over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            digest,
            state: None,
        }
    }
}

impl<D: Digest> OpenSslPbe<D> {
    /// The first `len` bytes of `D1 || D2 || ...`.
    fn derive(&mut self, len: usize) -> Result<Zeroizing<Vec<u8>>, PbeError> {
        let state = self.state.as_ref().ok_or(PbeError::NotInitialised)?;
        let mut output = Zeroizing::new(vec![0; len]);
        let mut d = Zeroizing::new(vec![0; self.digest.digest_size()]);
        self.digest.reset();
        for (index, chunk) in output.chunks_mut(d.len()).enumerate() {
            if index > 0 {
                self.digest.update(&d);
            }
            self.digest.update(&state.password);
            self.digest.update(&state.salt);
            self.digest.do_final(&mut d);
            chunk.copy_from_slice(&d[..chunk.len()]);
        }
        Ok(output)
    }
}

impl<D, P: PbeParams + ?Sized> PbeGeneratorInit<P> for OpenSslPbe<D> {
    type Error = PbeError;

    /// Copies the password and salt; the iteration count is ignored, as in BC. Constant time
    /// with respect to the password and salt.
    fn init(&mut self, params: &P) -> Result<(), PbeError> {
        self.state = Some(PbeState {
            password: Zeroizing::new(params.password().to_vec()),
            salt: Zeroizing::new(params.salt().to_vec()),
            iteration_count: 1,
        });
        Ok(())
    }
}

impl<D: Digest> PbeGenerator for OpenSslPbe<D> {
    type Error = PbeError;

    /// Fills `key` with the start of the output. Fails before `init`. Constant time with
    /// respect to the password and salt when the digest is; the lengths are public.
    fn derive_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        let output = self.derive(key.len())?;
        key.copy_from_slice(&output);
        Ok(())
    }

    /// Fills `key` and then `iv` from one output. Fails before `init`. Constant time with
    /// respect to the password and salt when the digest is; the lengths are public.
    fn derive_key_and_iv(&mut self, key: &mut [u8], iv: &mut [u8]) -> Result<(), PbeError> {
        let output = self.derive(key.len() + iv.len())?;
        let (key_bytes, iv_bytes) = output.split_at(key.len());
        key.copy_from_slice(key_bytes);
        iv.copy_from_slice(iv_bytes);
        Ok(())
    }

    /// The same bytes as [`derive_key`](Self::derive_key), as in BC. Constant time with
    /// respect to the password and salt when the digest is; the lengths are public.
    fn derive_mac_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        self.derive_key(key)
    }
}
