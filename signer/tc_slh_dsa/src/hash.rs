use alloc::vec;
use alloc::vec::Vec;

use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_sha::{Sha256Digest, Sha512Digest};

use crate::SlhDsaParameters;
use crate::adrs::Adrs;
use crate::params::Family;

/// H_msg 的結果：FORS 的訊息摘要與兩個索引。
pub(crate) struct IndexedDigest {
    pub(crate) digest: Vec<u8>,
    pub(crate) tree: u64,
    pub(crate) leaf: u32,
}

// One per signature or verification, so the size of the SHA2 variant does not matter
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Midstate {
    // SHA-256 of PK.seed padded to 64 bytes, and the digest of H and T_l padded to its block
    Sha2 { f: Sha256Digest, h: Sha2H },
    Shake,
}

#[derive(Clone)]
enum Sha2H {
    Sha256(Sha256Digest),
    Sha512(Sha512Digest),
}

/// BC 的 `SlhDsaEngine`：FIPS 205 第 11 節的 F、H、T_l、PRF、PRF_msg 與 H_msg，以 PK.seed 為
/// 前綴。SHA2 參數組先算好 PK.seed 那一塊的中間狀態。
pub(crate) struct Hasher {
    params: SlhDsaParameters,
    pk_seed: Vec<u8>,
    midstate: Midstate,
}

fn finish_into<D: Digest>(mut digest: D, out: &mut [u8]) {
    let mut full = [0u8; 64];
    let size = digest.digest_size();
    digest.do_final(&mut full[..size]);
    out.copy_from_slice(&full[..out.len()]);
}

fn hmac<D: Digest + Clone>(empty: D, key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let block = empty.byte_length();
    let mut pad = [0u8; 128];
    pad[..key.len()].copy_from_slice(key);
    let mut inner = empty.clone();
    let mut outer = empty;
    let mut ipad = [0u8; 128];
    let mut opad = [0u8; 128];
    for i in 0..block {
        ipad[i] = pad[i] ^ 0x36;
        opad[i] = pad[i] ^ 0x5c;
    }
    inner.update(&ipad[..block]);
    for part in parts {
        inner.update(part);
    }
    let size = inner.digest_size();
    let mut hash = [0u8; 64];
    inner.do_final(&mut hash[..size]);
    outer.update(&opad[..block]);
    outer.update(&hash[..size]);
    finish_into(outer, out);
}

fn mgf1<D: Digest + Clone>(empty: D, seed: &[u8], out: &mut [u8]) {
    let size = empty.digest_size();
    for (counter, chunk) in out.chunks_mut(size).enumerate() {
        let mut digest = empty.clone();
        digest.update(seed);
        digest.update(&(counter as u32).to_be_bytes());
        finish_into(digest, chunk);
    }
}

fn digest_of<D: Digest>(mut digest: D, parts: &[&[u8]]) -> Vec<u8> {
    for part in parts {
        digest.update(part);
    }
    let mut out = vec![0u8; digest.digest_size()];
    digest.do_final(&mut out);
    out
}

impl Hasher {
    pub(crate) fn new(params: SlhDsaParameters, pk_seed: &[u8]) -> Self {
        let n = params.n();
        let midstate = match params.family() {
            Family::Shake => Midstate::Shake,
            Family::Sha2 => {
                let zeros = [0u8; 128];
                let mut f = Sha256Digest::new();
                f.update(pk_seed);
                f.update(&zeros[..64 - n]);
                let h = if n == 16 {
                    Sha2H::Sha256(f.clone())
                } else {
                    let mut h = Sha512Digest::new();
                    h.update(pk_seed);
                    h.update(&zeros[..128 - n]);
                    Sha2H::Sha512(h)
                };
                Midstate::Sha2 { f, h }
            }
        };
        Self {
            params,
            pk_seed: pk_seed.to_vec(),
            midstate,
        }
    }

    fn shake(&self, adrs: &Adrs, parts: &[&[u8]], out: &mut [u8]) {
        let mut xof = ShakeDigest::new(256);
        xof.update(&self.pk_seed);
        xof.update(&adrs.0);
        for part in parts {
            xof.update(part);
        }
        xof.output_final(out);
    }

    // F and PRF: SHA-256 for every SHA2 set
    fn small(&self, adrs: &Adrs, parts: &[&[u8]], out: &mut [u8]) {
        match &self.midstate {
            Midstate::Shake => self.shake(adrs, parts, out),
            Midstate::Sha2 { f, .. } => {
                let mut digest = f.clone();
                digest.update(&adrs.compressed());
                for part in parts {
                    digest.update(part);
                }
                finish_into(digest, out);
            }
        }
    }

    // H and T_l: SHA-512 for the SHA2 sets above n = 16
    fn large(&self, adrs: &Adrs, parts: &[&[u8]], out: &mut [u8]) {
        match &self.midstate {
            Midstate::Shake => self.shake(adrs, parts, out),
            Midstate::Sha2 { h, .. } => {
                let compressed = adrs.compressed();
                match h {
                    Sha2H::Sha256(digest) => {
                        let mut digest = digest.clone();
                        digest.update(&compressed);
                        for part in parts {
                            digest.update(part);
                        }
                        finish_into(digest, out);
                    }
                    Sha2H::Sha512(digest) => {
                        let mut digest = digest.clone();
                        digest.update(&compressed);
                        for part in parts {
                            digest.update(part);
                        }
                        finish_into(digest, out);
                    }
                }
            }
        }
    }

    /// F：就地更新 n 位元組。
    pub(crate) fn f(&self, adrs: &Adrs, x: &mut [u8]) {
        let input: [u8; 32] = {
            let mut buf = [0u8; 32];
            buf[..x.len()].copy_from_slice(x);
            buf
        };
        self.small(adrs, &[&input[..x.len()]], x);
    }

    /// H(left ‖ right) 寫到 out。
    pub(crate) fn h(&self, adrs: &Adrs, left: &[u8], right: &[u8], out: &mut [u8]) {
        self.large(adrs, &[left, right], out);
    }

    /// T_l。
    pub(crate) fn t_l(&self, adrs: &Adrs, input: &[u8], out: &mut [u8]) {
        self.large(adrs, &[input], out);
    }

    /// PRF(PK.seed, SK.seed, ADRS)。
    pub(crate) fn prf(&self, adrs: &Adrs, sk_seed: &[u8], out: &mut [u8]) {
        self.small(adrs, &[sk_seed], out);
    }

    /// PRF_msg(SK.prf, opt_rand, M)，結果是簽章的 R。
    pub(crate) fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], message: &[u8], out: &mut [u8]) {
        match self.params.family() {
            Family::Shake => {
                let mut xof = ShakeDigest::new(256);
                xof.update(sk_prf);
                xof.update(opt_rand);
                xof.update(message);
                xof.output_final(out);
            }
            Family::Sha2 if self.params.n() == 16 => {
                hmac(Sha256Digest::new(), sk_prf, &[opt_rand, message], out)
            }
            Family::Sha2 => hmac(Sha512Digest::new(), sk_prf, &[opt_rand, message], out),
        }
    }

    /// H_msg(R, PK.seed, PK.root, M)，拆成 FORS 摘要、樹與葉的索引。
    pub(crate) fn h_msg(&self, r: &[u8], pk_root: &[u8], message: &[u8]) -> IndexedDigest {
        let p = &self.params;
        let fors_bytes = (p.a() * p.k()).div_ceil(8);
        let leaf_bits = p.h_prime();
        let tree_bits = p.h() - leaf_bits;
        let leaf_bytes = leaf_bits.div_ceil(8);
        let tree_bytes = tree_bits.div_ceil(8);
        let mut output = vec![0u8; fors_bytes + tree_bytes + leaf_bytes];
        let pk_seed = &self.pk_seed[..];
        match p.family() {
            Family::Shake => {
                let mut xof = ShakeDigest::new(256);
                for part in [r, pk_seed, pk_root, message] {
                    xof.update(part);
                }
                xof.output_final(&mut output);
            }
            Family::Sha2 if p.n() == 16 => {
                let inner = digest_of(Sha256Digest::new(), &[r, pk_seed, pk_root, message]);
                let seed = [r, pk_seed, &inner].concat();
                mgf1(Sha256Digest::new(), &seed, &mut output);
            }
            Family::Sha2 => {
                let inner = digest_of(Sha512Digest::new(), &[r, pk_seed, pk_root, message]);
                let seed = [r, pk_seed, &inner].concat();
                mgf1(Sha512Digest::new(), &seed, &mut output);
            }
        }
        let tree = output[fors_bytes..fors_bytes + tree_bytes]
            .iter()
            .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte))
            & (u64::MAX >> (64 - tree_bits));
        let leaf = output[fors_bytes + tree_bytes..]
            .iter()
            .fold(0u32, |acc, &byte| (acc << 8) | u32::from(byte))
            & (u32::MAX >> (32 - leaf_bits));
        output.truncate(fors_bytes);
        IndexedDigest {
            digest: output,
            tree,
            leaf,
        }
    }
}
