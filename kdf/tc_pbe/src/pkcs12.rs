use alloc::vec;

use tc_digest::Digest;
use tc_zeroize::Zeroizing;

use crate::state::PbeState;
use crate::{PbeError, PbeGenerator, PbeGeneratorInit, PbeParams};

const KEY_MATERIAL: u8 = 1;
const IV_MATERIAL: u8 = 2;
const MAC_MATERIAL: u8 = 3;

/// The PKCS#12 key derivation of RFC 7292 appendix B, BC's `Pkcs12ParametersGenerator`, for a
/// password encoded by `pkcs12_password_to_bytes`.
///
/// The key, IV and MAC key are each derived on their own, with the ID byte 1, 2 or 3, so the
/// MAC key differs from the cipher key. Every block hashes `D || I` and iterates; `I`, the salt
/// and password each repeated to a whole number of digest blocks, then gets each block raised
/// by the last hash plus one.
///
/// The password and salt copied at `init` are wiped when replaced and on drop, and so are `I`
/// and every hash.
pub struct Pkcs12<D> {
    digest: D,
    state: Option<PbeState>,
}

impl<D> Pkcs12<D> {
    /// A generator over `digest`, not yet initialized. Constant time.
    pub const fn new(digest: D) -> Self {
        Self {
            digest,
            state: None,
        }
    }
}

impl<D: Digest> Pkcs12<D> {
    /// Fills `output` with the material of the ID byte `id`.
    fn derive(&mut self, id: u8, output: &mut [u8]) -> Result<(), PbeError> {
        let state = self.state.as_ref().ok_or(PbeError::NotInitialised)?;
        let u = self.digest.digest_size();
        let v = self.digest.byte_length();

        let d = vec![id; v];
        let salt_len = state.salt.len().div_ceil(v) * v;
        let password_len = state.password.len().div_ceil(v) * v;
        let mut i = Zeroizing::new(vec![0; salt_len + password_len]);
        let (s, p) = i.split_at_mut(salt_len);
        repeat_fill(&state.salt, s);
        repeat_fill(&state.password, p);

        let mut a = Zeroizing::new(vec![0; u]);
        let mut b = Zeroizing::new(vec![0; v]);
        self.digest.reset();
        for chunk in output.chunks_mut(u) {
            self.digest.update(&d);
            self.digest.update(&i);
            self.digest.do_final(&mut a);
            for _ in 1..state.iteration_count {
                self.digest.update(&a);
                self.digest.do_final(&mut a);
            }
            repeat_fill(&a, &mut b);
            for block in i.chunks_mut(v) {
                add_one_more(block, &b);
            }
            chunk.copy_from_slice(&a[..chunk.len()]);
        }
        Ok(())
    }
}

/// Fills `z` with `x` over and over. Constant time with respect to the bytes.
fn repeat_fill(x: &[u8], z: &mut [u8]) {
    for (z, x) in z.iter_mut().zip(x.iter().cycle()) {
        *z = *x;
    }
}

/// `a = (a + b + 1) mod 2^(8 * len)`, both big-endian and of one length, BC's `Adjust`. Constant
/// time: the carry is added without branching.
fn add_one_more(a: &mut [u8], b: &[u8]) {
    let mut carry = 1u16;
    for (a, b) in a.iter_mut().rev().zip(b.iter().rev()) {
        let sum = u16::from(*a) + u16::from(*b) + carry;
        *a = sum as u8;
        carry = sum >> 8;
    }
}

impl<D, P: PbeParams + ?Sized> PbeGeneratorInit<P> for Pkcs12<D> {
    type Error = PbeError;

    /// Copies the password and salt. An iteration count of 0, which BC runs as 1, is refused
    /// before anything changes. Constant time with respect to the password and salt.
    fn init(&mut self, params: &P) -> Result<(), PbeError> {
        self.state = Some(PbeState::copy(params)?);
        Ok(())
    }
}

impl<D: Digest> PbeGenerator for Pkcs12<D> {
    type Error = PbeError;

    /// Fills `key` with key material, ID byte 1. Fails before `init`. Constant time with
    /// respect to the password and salt when the digest is; the iteration count and lengths are
    /// public.
    fn derive_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        self.derive(KEY_MATERIAL, key)
    }

    /// Fills `key` with key material and `iv` with IV material, ID bytes 1 and 2. Fails before
    /// `init`. Constant time with respect to the password and salt when the digest is; the
    /// iteration count and lengths are public.
    fn derive_key_and_iv(&mut self, key: &mut [u8], iv: &mut [u8]) -> Result<(), PbeError> {
        self.derive(KEY_MATERIAL, key)?;
        self.derive(IV_MATERIAL, iv)
    }

    /// Fills `key` with MAC material, ID byte 3. Fails before `init`. Constant time with
    /// respect to the password and salt when the digest is; the iteration count and lengths are
    /// public.
    fn derive_mac_key(&mut self, key: &mut [u8]) -> Result<(), PbeError> {
        self.derive(MAC_MATERIAL, key)
    }
}
