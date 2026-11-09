use alloc::vec;
use alloc::vec::Vec;

use tc_constant_time::ConstantTimeEq;
use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_zeroize::{Zeroize, Zeroizing};

use crate::poly::{N, Poly, vector};
use crate::{MlDsaError, MlDsaParameters};

const MAX_ATTEMPTS: usize = 1000;

/// 私鑰的各段編碼。
pub(crate) struct KeyMaterial {
    pub(crate) rho: [u8; 32],
    pub(crate) k: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s1: Vec<u8>,
    pub(crate) s2: Vec<u8>,
    pub(crate) t0: Vec<u8>,
    pub(crate) t1: Vec<u8>,
}

fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = ShakeDigest::new(256);
    for part in parts {
        xof.update(part);
    }
    xof.output_final(out);
}

/// FIPS 204 的 ExpandA：Â[i][j] = RejNTTPoly(ρ ‖ j ‖ i)。只依公開的 ρ。
fn expand_matrix(p: &MlDsaParameters, rho: &[u8]) -> Vec<Vec<Poly>> {
    (0..p.k())
        .map(|i| {
            (0..p.l())
                .map(|j| {
                    let mut poly = Poly::default();
                    poly.uniform(rho, ((i << 8) + j) as u16);
                    poly
                })
                .collect()
        })
        .collect()
}

/// t = Â ∘ v，每列累加。常數時間。
fn matrix_multiply(matrix: &[Vec<Poly>], v: &[Poly], t: &mut [Poly]) {
    let mut product = Poly::default();
    for (row, out) in matrix.iter().zip(t.iter_mut()) {
        out.pointwise_montgomery(&row[0], &v[0]);
        for (a, b) in row.iter().zip(v).skip(1) {
            product.pointwise_montgomery(a, b);
            out.add(&product);
        }
    }
    product.zeroize();
}

fn for_each(v: &mut [Poly], f: impl Fn(&mut Poly)) {
    for poly in v {
        f(poly);
    }
}

/// t = A·s1 + s2，拆成 (t1, t0)。對 s1、s2 是常數時間。
fn compute_t(
    p: &MlDsaParameters,
    rho: &[u8],
    s1: &[Poly],
    s2: &[Poly],
) -> (Vec<Poly>, Zeroizing<Vec<Poly>>) {
    let matrix = expand_matrix(p, rho);
    let mut s1_hat = Zeroizing::new(s1.to_vec());
    for_each(&mut s1_hat, Poly::ntt);
    let mut t1 = vector(p.k());
    matrix_multiply(&matrix, &s1_hat, &mut t1);
    for_each(&mut t1, Poly::reduce);
    for_each(&mut t1, Poly::inverse_ntt_to_mont);
    for (t, s) in t1.iter_mut().zip(s2) {
        t.add(s);
    }
    for_each(&mut t1, Poly::conditional_add_q);
    let mut t0 = Zeroizing::new(vector(p.k()));
    for (high, low) in t1.iter_mut().zip(t0.iter_mut()) {
        high.power2round(low);
    }
    (t1, t0)
}

fn pack_t1(p: &MlDsaParameters, t1: &[Poly]) -> Vec<u8> {
    let mut out = vec![0u8; p.k() * 320];
    for (poly, chunk) in t1.iter().zip(out.chunks_exact_mut(320)) {
        poly.pack_t1(chunk);
    }
    out
}

fn unpack_secret(
    p: &MlDsaParameters,
    s1: &[u8],
    s2: &[u8],
    t0: &[u8],
) -> [Zeroizing<Vec<Poly>>; 3] {
    let eta_bytes = p.eta_packed_bytes();
    let mut s1v = Zeroizing::new(vector(p.l()));
    for (poly, chunk) in s1v.iter_mut().zip(s1.chunks_exact(eta_bytes)) {
        poly.unpack_eta(chunk, p.eta());
    }
    let mut s2v = Zeroizing::new(vector(p.k()));
    for (poly, chunk) in s2v.iter_mut().zip(s2.chunks_exact(eta_bytes)) {
        poly.unpack_eta(chunk, p.eta());
    }
    let mut t0v = Zeroizing::new(vector(p.k()));
    for (poly, chunk) in t0v.iter_mut().zip(t0.chunks_exact(416)) {
        poly.unpack_t0(chunk);
    }
    [s1v, s2v, t0v]
}

/// tr = H(ρ ‖ t1, 64)。常數時間。
pub(crate) fn public_key_hash(rho: &[u8], t1: &[u8]) -> [u8; 64] {
    let mut tr = [0u8; 64];
    shake256(&[rho, t1], &mut tr);
    tr
}

/// BC 的 `GenerateKeyPairInternal`（ML-DSA.KeyGen_internal）。對 seed 是常數時間，除了 s1、s2
/// 的拒絕取樣次數。
pub(crate) fn generate_key_pair(p: &MlDsaParameters, seed: &[u8; 32]) -> KeyMaterial {
    let mut expanded = Zeroizing::new([0u8; 128]);
    shake256(&[seed, &[p.k() as u8, p.l() as u8]], &mut expanded[..]);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&expanded[..32]);
    let rho_prime = &expanded[32..96];
    let mut k = [0u8; 32];
    k.copy_from_slice(&expanded[96..]);

    let mut s1 = Zeroizing::new(vector(p.l()));
    for (j, poly) in s1.iter_mut().enumerate() {
        poly.uniform_eta(rho_prime, j as u16, p.eta());
    }
    let mut s2 = Zeroizing::new(vector(p.k()));
    for (j, poly) in s2.iter_mut().enumerate() {
        poly.uniform_eta(rho_prime, (p.l() + j) as u16, p.eta());
    }

    let (t1, t0) = compute_t(p, &rho, &s1, &s2);
    let t1 = pack_t1(p, &t1);
    let tr = public_key_hash(&rho, &t1);

    let eta_bytes = p.eta_packed_bytes();
    let mut s1_enc = vec![0u8; p.l() * eta_bytes];
    for (poly, chunk) in s1.iter().zip(s1_enc.chunks_exact_mut(eta_bytes)) {
        poly.pack_eta(chunk, p.eta());
    }
    let mut s2_enc = vec![0u8; p.k() * eta_bytes];
    for (poly, chunk) in s2.iter().zip(s2_enc.chunks_exact_mut(eta_bytes)) {
        poly.pack_eta(chunk, p.eta());
    }
    let mut t0_enc = vec![0u8; p.k() * 416];
    for (poly, chunk) in t0.iter().zip(t0_enc.chunks_exact_mut(416)) {
        poly.pack_t0(chunk);
    }
    KeyMaterial {
        rho,
        k,
        tr,
        s1: s1_enc,
        s2: s2_enc,
        t0: t0_enc,
        t1,
    }
}

/// BC 的 `DeriveT1`：由私鑰的編碼重算 t1。對 s1、s2 是常數時間。
pub(crate) fn derive_t1(
    p: &MlDsaParameters,
    rho: &[u8],
    s1: &[u8],
    s2: &[u8],
    t0: &[u8],
) -> Vec<u8> {
    let [s1, s2, _] = unpack_secret(p, s1, s2, t0);
    let (t1, _) = compute_t(p, rho, &s1, &s2);
    pack_t1(p, &t1)
}

/// BC 的 `MsgRepEndSignInternal`（ML-DSA.Sign_internal）：`digest` 已吸收 tr ‖ M′，算出 μ 並
/// 簽到 `sig`。拒絕取樣的圈數依秘密而定，FIPS 204 本身如此；每一圈只透露是否被拒絕。
pub(crate) fn sign(
    p: &MlDsaParameters,
    mut digest: ShakeDigest,
    key: &KeyMaterial,
    rnd: &[u8; 32],
    sig: &mut [u8],
) -> Result<(), MlDsaError> {
    let mut mu = [0u8; 64];
    digest.output_final(&mut mu);
    let mut rho_prime = Zeroizing::new([0u8; 64]);
    shake256(&[&key.k, rnd, &mu], &mut rho_prime[..]);

    let [mut s1, mut s2, mut t0] = unpack_secret(p, &key.s1, &key.s2, &key.t0);
    for_each(&mut s1, Poly::ntt);
    for_each(&mut s2, Poly::ntt);
    for_each(&mut t0, Poly::ntt);
    let matrix = expand_matrix(p, &key.rho);

    let (k, l) = (p.k(), p.l());
    let mut y = Zeroizing::new(vector(l));
    let mut z = Zeroizing::new(vector(l));
    let mut w1 = Zeroizing::new(vector(k));
    let mut w0 = Zeroizing::new(vector(k));
    let mut h = Zeroizing::new(vector(k));
    let mut c = Zeroizing::new(Poly::default());
    let mut w1_packed = Zeroizing::new(vec![0u8; k * p.w1_packed_bytes()]);
    let c_tilde = p.c_tilde();

    for attempt in 0..MAX_ATTEMPTS {
        let nonce = attempt as u16;
        for (i, poly) in y.iter_mut().enumerate() {
            poly.uniform_gamma1(
                &rho_prime[..],
                (l as u16).wrapping_mul(nonce).wrapping_add(i as u16),
                p.gamma1(),
            );
        }
        z.clone_from_slice(&y);
        for_each(&mut z, Poly::ntt);

        matrix_multiply(&matrix, &z, &mut w1);
        for_each(&mut w1, Poly::reduce);
        for_each(&mut w1, Poly::inverse_ntt_to_mont);
        for_each(&mut w1, Poly::conditional_add_q);
        for (high, low) in w1.iter_mut().zip(w0.iter_mut()) {
            high.decompose(low, p.gamma2());
        }
        for (poly, chunk) in w1
            .iter()
            .zip(w1_packed.chunks_exact_mut(p.w1_packed_bytes()))
        {
            poly.pack_w1(chunk, p.gamma2());
        }
        shake256(&[&mu, &w1_packed], &mut sig[..c_tilde]);

        c.challenge(&sig[..c_tilde], p.tau());
        c.ntt();

        for (out, s) in z.iter_mut().zip(s1.iter()) {
            out.pointwise_montgomery(&c, s);
        }
        for_each(&mut z, Poly::inverse_ntt_to_mont);
        for (out, add) in z.iter_mut().zip(y.iter()) {
            out.add(add);
        }
        for_each(&mut z, Poly::reduce);
        if z.iter().any(|poly| poly.check_norm(p.gamma1() - p.beta())) {
            continue;
        }

        for (out, s) in h.iter_mut().zip(s2.iter()) {
            out.pointwise_montgomery(&c, s);
        }
        for_each(&mut h, Poly::inverse_ntt_to_mont);
        for (out, sub) in w0.iter_mut().zip(h.iter()) {
            out.subtract(sub);
        }
        for_each(&mut w0, Poly::reduce);
        if w0.iter().any(|poly| poly.check_norm(p.gamma2() - p.beta())) {
            continue;
        }

        for (out, t) in h.iter_mut().zip(t0.iter()) {
            out.pointwise_montgomery(&c, t);
        }
        for_each(&mut h, Poly::inverse_ntt_to_mont);
        for_each(&mut h, Poly::reduce);
        if h.iter().any(|poly| poly.check_norm(p.gamma2())) {
            continue;
        }

        for (out, add) in w0.iter_mut().zip(h.iter()) {
            out.add(add);
        }
        for_each(&mut w0, Poly::conditional_add_q);
        let mut ones = 0;
        for i in 0..k {
            let (hint, low, high) = (&mut h[i], &w0[i], &w1[i]);
            ones += hint.make_hint(low, high, p.gamma2());
        }
        if ones > p.omega() {
            continue;
        }

        pack_signature(p, sig, &z, &h);
        return Ok(());
    }
    Err(MlDsaError::SigningFailed)
}

fn pack_signature(p: &MlDsaParameters, sig: &mut [u8], z: &[Poly], h: &[Poly]) {
    let z_bytes = p.z_packed_bytes();
    let mut end = p.c_tilde();
    for poly in z {
        poly.pack_z(&mut sig[end..end + z_bytes], p.gamma1());
        end += z_bytes;
    }
    let hints = &mut sig[end..end + p.omega() + p.k()];
    hints.fill(0);
    let mut count = 0;
    for (i, poly) in h.iter().enumerate() {
        for (j, &coefficient) in poly.0.iter().enumerate() {
            if coefficient != 0 {
                hints[count] = j as u8;
                count += 1;
            }
        }
        hints[p.omega() + i] = count as u8;
    }
}

fn unpack_signature(p: &MlDsaParameters, sig: &[u8], z: &mut [Poly], h: &mut [Poly]) -> bool {
    let z_bytes = p.z_packed_bytes();
    let mut end = p.c_tilde();
    for poly in z.iter_mut() {
        poly.unpack_z(&sig[end..end + z_bytes], p.gamma1());
        end += z_bytes;
    }
    let hints = &sig[end..end + p.omega() + p.k()];
    let mut k = 0;
    for (i, poly) in h.iter_mut().enumerate() {
        poly.0 = [0; N];
        let limit = usize::from(hints[p.omega() + i]);
        if limit < k || limit > p.omega() {
            return false;
        }
        for j in k..limit {
            if j > k && hints[j] <= hints[j - 1] {
                return false;
            }
            poly.0[usize::from(hints[j])] = 1;
        }
        k = limit;
    }
    hints[k..p.omega()].iter().all(|&byte| byte == 0)
}

/// BC 的 `MsgRepEndVerifyInternal`（ML-DSA.Verify_internal）。變動時間：只能用於公開值。
pub(crate) fn verify(
    p: &MlDsaParameters,
    mut digest: ShakeDigest,
    rho: &[u8],
    t1: &[u8],
    sig: &[u8],
) -> bool {
    if sig.len() != p.signature_length() {
        return false;
    }
    let (k, l) = (p.k(), p.l());
    let mut z = vector(l);
    let mut h = vector(k);
    if !unpack_signature(p, sig, &mut z, &mut h) {
        return false;
    }
    if z.iter().any(|poly| poly.check_norm(p.gamma1() - p.beta())) {
        return false;
    }

    let mut mu = [0u8; 64];
    digest.output_final(&mut mu);
    let c_tilde = &sig[..p.c_tilde()];
    let mut c = Poly::default();
    c.challenge(c_tilde, p.tau());

    let matrix = expand_matrix(p, rho);
    for_each(&mut z, Poly::ntt);
    let mut w1 = vector(k);
    matrix_multiply(&matrix, &z, &mut w1);

    c.ntt();
    let mut t1v = vector(k);
    for (poly, chunk) in t1v.iter_mut().zip(t1.chunks_exact(320)) {
        poly.unpack_t1(chunk);
        poly.shift_left();
        poly.ntt();
        let shifted = poly.clone();
        poly.pointwise_montgomery(&c, &shifted);
    }
    for (out, sub) in w1.iter_mut().zip(&t1v) {
        out.subtract(sub);
    }
    for_each(&mut w1, Poly::reduce);
    for_each(&mut w1, Poly::inverse_ntt_to_mont);
    for_each(&mut w1, Poly::conditional_add_q);
    for (poly, hint) in w1.iter_mut().zip(&h) {
        poly.use_hint(hint, p.gamma2());
    }
    let mut w1_packed = vec![0u8; k * p.w1_packed_bytes()];
    for (poly, chunk) in w1
        .iter()
        .zip(w1_packed.chunks_exact_mut(p.w1_packed_bytes()))
    {
        poly.pack_w1(chunk, p.gamma2());
    }
    let mut expected = vec![0u8; p.c_tilde()];
    shake256(&[&mu, &w1_packed], &mut expected);
    expected.as_slice().ct_eq(c_tilde).unwrap_u8() == 1
}
