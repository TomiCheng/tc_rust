use alloc::vec;
use alloc::vec::Vec;

use tc_digest::Digest;
use tc_macs::{Hmac, KeyRef, Mac, MacError, MacInit};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::hkdf::HkdfParams;
use crate::{Kdf, KdfError, KdfInit};

/// HKDF (RFC 5869) over HMAC with the digest `D`, BC's `HkdfBytesGenerator`.
///
/// `init` runs the extract step, unless the parameters skip it, and `generate_bytes` the
/// expand step. As in BC, each call continues where the last one stopped, up to
/// `255 * HashLen` bytes in all until the next `init`. The pseudorandom key lives in the HMAC,
/// which wipes it on drop; the last block and `info` are wiped when replaced and on drop.
pub struct Hkdf<D> {
    hmac: Hmac<D>,
    info: Vec<u8>,
    current_t: Vec<u8>,
    generated: usize,
    initialized: bool,
}

impl<D: Digest> Hkdf<D> {
    /// A function over `digest`, not yet initialized. Constant time.
    ///
    /// # Panics
    ///
    /// As [`Hmac::new`]: when the digest's block is shorter than 16 bytes or than its output.
    pub fn new(digest: D) -> Self {
        let hmac = Hmac::new(digest);
        let hash_len = hmac.mac_size();
        Self {
            hmac,
            info: Vec::new(),
            current_t: vec![0; hash_len],
            generated: 0,
            initialized: false,
        }
    }

    /// `T(n) = HMAC(PRK, T(n - 1) || info || n)`, into `current_t`. The caller keeps `n` at or
    /// below 255.
    fn expand_next(&mut self) -> Result<(), MacError> {
        let n = self.generated / self.current_t.len() + 1;
        if self.generated != 0 {
            self.hmac.update(&self.current_t)?;
        }
        self.hmac.update(&self.info)?;
        self.hmac.update(&[n as u8])?;
        self.hmac.do_final(&mut self.current_t)?;
        Ok(())
    }
}

impl<D: Digest, P: HkdfParams + ?Sized> KdfInit<P> for Hkdf<D> {
    type Error = MacError;

    /// Runs the extract step, or keys the HMAC with the IKM when the parameters skip it.
    /// Constant time with respect to the IKM and salt when the digest is; only their lengths
    /// decide the work.
    fn init(&mut self, params: &P) -> Result<(), MacError> {
        self.initialized = false;
        let hash_len = self.current_t.len();
        if params.skip_extract() {
            let Ok(()) = self.hmac.init(&KeyRef::new(params.ikm()));
        } else {
            let salt = params.salt();
            if salt.is_empty() {
                let Ok(()) = self.hmac.init(&KeyRef::new(&vec![0; hash_len]));
            } else {
                let Ok(()) = self.hmac.init(&KeyRef::new(salt));
            }
            self.hmac.update(params.ikm())?;
            let mut prk = Zeroizing::new(vec![0; hash_len]);
            self.hmac.do_final(&mut prk)?;
            let Ok(()) = self.hmac.init(&KeyRef::new(&prk));
        }
        self.info.zeroize();
        self.info = params.info().to_vec();
        self.current_t.zeroize();
        self.current_t.resize(hash_len, 0);
        self.generated = 0;
        self.initialized = true;
        Ok(())
    }
}

impl<D: Digest> Kdf for Hkdf<D> {
    type Error = KdfError<MacError>;

    /// Continues the output where the last call stopped. Fails before `init`, or when the
    /// output since `init` would pass `255 * HashLen` bytes. Constant time with respect to the
    /// key when the digest is; the output length is public.
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(KdfError::NotInitialised);
        }
        let hash_len = self.current_t.len();
        let length = output.len();
        if length > 255 * hash_len - self.generated {
            return Err(KdfError::OutputTooLong);
        }

        let mut output = output;
        let position = self.generated % hash_len;
        if position != 0 {
            let count = (hash_len - position).min(output.len());
            output[..count].copy_from_slice(&self.current_t[position..position + count]);
            self.generated += count;
            output = &mut output[count..];
        }
        for block in output.chunks_mut(hash_len) {
            self.expand_next().map_err(KdfError::Mac)?;
            block.copy_from_slice(&self.current_t[..block.len()]);
            self.generated += block.len();
        }
        Ok(length)
    }
}

impl<D> Drop for Hkdf<D> {
    fn drop(&mut self) {
        self.info.zeroize();
        self.current_t.zeroize();
    }
}
