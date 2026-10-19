use crate::DsaKCalculator;
use alloc::vec;
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_macs::{Hmac, KeyRef, Mac, MacInit};
use tc_zeroize::{Zeroize, Zeroizing};

const KEYED: &str = "the HMAC is keyed";

/// BC's `HMacDsaKCalculator`, RFC 6979's deterministic k: drawn by HMAC over the digest `D`
/// from d and the message. K and V are wiped on drop.
pub struct HMacDsaKCalculator<D> {
    hmac: Hmac<D>,
    k: Zeroizing<Vec<u8>>,
    v: Zeroizing<Vec<u8>>,
    n: Option<PaddedBigUint>,
}

impl<D: Digest> HMacDsaKCalculator<D> {
    /// A calculator on HMAC over `digest`, to be initialized. Constant time.
    pub fn new(digest: D) -> Self {
        let hmac = Hmac::new(digest);
        let size = hmac.mac_size();
        Self {
            hmac,
            k: Zeroizing::new(vec![0; size]),
            v: Zeroizing::new(vec![0; size]),
            n: None,
        }
    }
}

impl<D: Digest> DsaKCalculator<PaddedBigUint> for HMacDsaKCalculator<D> {
    /// RFC 6979 3.2 b–g. Constant time in d, as the digest is; n and the message are public.
    fn init(&mut self, n: &PaddedBigUint, d: &PaddedBigUint, message: &[u8]) {
        let size = byte_length(n);
        let mut m = bits_to_int(n, message);
        if m >= *n {
            m -= n;
        }
        let mut xm = Zeroizing::new(vec![0; 2 * size]);
        int_to_octets(d, &mut xm[..size]);
        int_to_octets(&m, &mut xm[size..]);

        self.k.fill(0);
        self.v.fill(1);
        rekey(&mut self.hmac, &mut self.k, &mut self.v, 0x00, &xm);
        rekey(&mut self.hmac, &mut self.k, &mut self.v, 0x01, &xm);
        self.n = Some(n.clone());
    }

    /// RFC 6979 3.2 h. Constant time in k, apart from how many are drawn, as in all drawing
    /// by rejection.
    fn next_k(&mut self) -> PaddedBigUint {
        let n = self.n.as_ref().expect("the calculator is initialized");
        let one = PaddedBigUint::from(1u8);
        let mut t = Zeroizing::new(vec![0; byte_length(n)]);
        let block = self.v.len();
        loop {
            for chunk in t.chunks_mut(block) {
                step(&mut self.hmac, &mut self.v);
                chunk.copy_from_slice(&self.v[..chunk.len()]);
            }
            let mut k = bits_to_int(n, &t);
            if k >= one && k < *n {
                return k;
            }
            k.zeroize();
            rekey(&mut self.hmac, &mut self.k, &mut self.v, 0x00, &[]);
        }
    }
}

fn byte_length(n: &PaddedBigUint) -> usize {
    n.bits().div_ceil(8) as usize
}

// RFC 6979 2.3.2: the leftmost qlen bits of `input`.
fn bits_to_int(n: &PaddedBigUint, input: &[u8]) -> PaddedBigUint {
    let Ok(mut value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(input);
    let excess = (input.len() * 8).saturating_sub(n.bits() as usize);
    if excess > 0 {
        value >>= excess as u32;
    }
    value
}

// RFC 6979 2.3.3: `value`, below 2^(8 · output.len()), big-endian into all of `output`.
fn int_to_octets(value: &PaddedBigUint, output: &mut [u8]) {
    let bytes = Zeroizing::new(ArrayEncoding::<u8>::to_be(value));
    let length = bytes.len().min(output.len());
    let (padding, tail) = output.split_at_mut(output.len() - length);
    padding.fill(0);
    tail.copy_from_slice(&bytes[bytes.len() - length..]);
}

// K = HMAC_K(V || marker || extra), then V = HMAC_K(V), leaving the HMAC keyed with the new K.
fn rekey<D: Digest>(hmac: &mut Hmac<D>, k: &mut [u8], v: &mut [u8], marker: u8, extra: &[u8]) {
    let Ok(()) = hmac.init(&KeyRef::new(k));
    for part in [&*v, &[marker][..], extra] {
        hmac.update(part).expect(KEYED);
    }
    hmac.do_final(k).expect(KEYED);
    let Ok(()) = hmac.init(&KeyRef::new(k));
    step(hmac, v);
}

// V = HMAC_K(V), the HMAC keyed with K.
fn step<D: Digest>(hmac: &mut Hmac<D>, v: &mut [u8]) {
    hmac.update(v).expect(KEYED);
    hmac.do_final(v).expect(KEYED);
}
