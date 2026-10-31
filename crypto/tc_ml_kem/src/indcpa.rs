use crate::MlKemParameters;
use crate::poly::Poly;
use crate::poly_vec::PolyVec;
use crate::reduce::Q;
use alloc::vec::Vec;
use tc_digest::{Digest, Xof};
use tc_keccak::{Sha3Digest, ShakeDigest};
use tc_zeroize::Zeroizing;

/// SHAKE128 的區塊長度。
const SHAKE128_RATE: usize = 168;

/// BC 的 `NumMatrixBlocks`：一次擠出的區塊數，通常已夠取 256 個係數。
const MATRIX_BLOCKS: usize = 3;

/// BC 的 `GenerateMatrixA`（FIPS 203 的 SampleNTT）：A[i][j] 由 SHAKE128(ρ ‖ j ‖ i) 拒絕
/// 取樣，`transpose` 時是 Aᵀ。變動時間：只能用於公開值，ρ 是公鑰的一部分。
fn matrix(params: &MlKemParameters, rho: &[u8], transpose: bool) -> Vec<PolyVec> {
    let k = params.k();
    (0..k)
        .map(|i| {
            PolyVec::from_fn(k, |j| {
                let (x, y) = if transpose { (i, j) } else { (j, i) };
                sample_ntt(rho, x as u8, y as u8)
            })
        })
        .collect()
}

/// 一個多項式的拒絕取樣：每 3 個位元組給兩個 12 位元的候選值，小於 q 的留下。先擠
/// [`MATRIX_BLOCKS`] 個區塊，不夠再一次擠一個。變動時間：只能用於公開值。
fn sample_ntt(rho: &[u8], x: u8, y: u8) -> Poly {
    let mut xof = ShakeDigest::new(128);
    xof.update(&rho[..32]);
    xof.update(&[x, y]);
    let mut poly = Poly::zero();
    let mut count = 0;
    let mut block = [0u8; MATRIX_BLOCKS * SHAKE128_RATE];
    let mut length = block.len();
    xof.output(&mut block);
    loop {
        for chunk in block[..length].chunks_exact(3) {
            let t = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], 0]);
            for candidate in [(t & 0xFFF) as i16, (t >> 12) as i16] {
                if count < 256 && candidate < Q {
                    poly.coeffs[count] = candidate;
                    count += 1;
                }
            }
        }
        if count == 256 {
            return poly;
        }
        length = SHAKE128_RATE;
        xof.output(&mut block[..length]);
    }
}

/// G 或 H 之類的 SHA3：`inputs` 依序串接後的雜湊寫進 `output`。常數時間程度同 SHA3。
pub(crate) fn sha3(bits: usize, inputs: &[&[u8]], output: &mut [u8]) {
    let mut digest = Sha3Digest::new(bits);
    for input in inputs {
        digest.update(input);
    }
    digest.do_final(output);
}

/// k 個以 `seed` 與遞增 nonce 取樣的雜訊多項式。常數時間：只依 η 與 k。
fn noise_vector(k: usize, eta: u8, seed: &[u8], nonce: &mut u8) -> PolyVec {
    PolyVec::from_fn(k, |_| {
        let poly = Poly::noise(eta, seed, *nonce);
        *nonce += 1;
        poly
    })
}

/// BC 的 `IndCpa.GenerateKeyPair`（FIPS 203 的 K-PKE.KeyGen）：(ρ, σ) = G(d ‖ k)，
/// t̂ = Â ∘ ŝ + ê；寫出 dk_PKE = ŝ 的編碼與 ek = t̂ 的編碼 ‖ ρ。對 d 與 s 是常數時間；Â 只依
/// 公開的 ρ。
pub(crate) fn generate_key_pair(params: &MlKemParameters, d: &[u8], dk: &mut [u8], ek: &mut [u8]) {
    let k = params.k();
    let mut seeds = Zeroizing::new([0u8; 64]);
    sha3(512, &[&d[..32], &[k as u8]], &mut seeds[..]);
    let (rho, sigma) = seeds.split_at(32);
    let a = matrix(params, rho, false);
    let mut nonce = 0;
    let mut s = noise_vector(k, params.eta1(), sigma, &mut nonce);
    let mut e = noise_vector(k, params.eta1(), sigma, &mut nonce);
    s.ntt();
    e.ntt();
    let mut t = PolyVec::from_fn(k, |i| {
        let mut poly = PolyVec::inner_product(&a[i], &s);
        poly.convert_to_mont();
        poly
    });
    t.add(&e);
    t.reduce();
    s.write_bytes(dk);
    t.write_bytes(ek);
    ek[384 * k..].copy_from_slice(rho);
}

/// BC 的 `IndCpa.Encrypt`（FIPS 203 的 K-PKE.Encrypt）：以 `coins` 取樣 r、e₁、e₂，
/// u = Aᵀr + e₁，v = tᵀr + e₂ + Decompress(m)，壓縮寫進 `ciphertext`。對 m 與 coins 是常數
/// 時間；Aᵀ 只依公開的 ρ。
pub(crate) fn encrypt(
    params: &MlKemParameters,
    ek: &[u8],
    message: &[u8],
    coins: &[u8],
    ciphertext: &mut [u8],
) {
    let k = params.k();
    let t = PolyVec::from_bytes(k, ek);
    let rho = &ek[384 * k..384 * k + 32];
    let a_transposed = matrix(params, rho, true);
    let mut nonce = 0;
    let mut r = noise_vector(k, params.eta1(), coins, &mut nonce);
    let e1 = noise_vector(k, 2, coins, &mut nonce);
    let e2 = Poly::noise(2, coins, nonce);
    r.ntt();
    let mut u = PolyVec::from_fn(k, |i| PolyVec::inner_product(&a_transposed[i], &r));
    let mut v = PolyVec::inner_product(&t, &r);
    u.inverse_ntt_to_mont();
    v.inverse_ntt_to_mont();
    u.add(&e1);
    v.add(&e2);
    v.add(&Poly::from_msg(message));
    u.reduce();
    v.reduce();
    let (cu, cv) = ciphertext.split_at_mut(params.poly_vec_compressed_bytes());
    u.compress(cu);
    v.compress(cv);
}

/// BC 的 `IndCpa.Decrypt`（FIPS 203 的 K-PKE.Decrypt）：w = v − sᵀu，取出 m。對 s 與 m 是
/// 常數時間。
pub(crate) fn decrypt(
    params: &MlKemParameters,
    ciphertext: &[u8],
    dk: &[u8],
    message: &mut [u8; 32],
) {
    let k = params.k();
    let (cu, cv) = ciphertext.split_at(params.poly_vec_compressed_bytes());
    let mut u = PolyVec::decompress(k, cu);
    let v = Poly::decompress(cv);
    let s = PolyVec::from_bytes(k, dk);
    u.ntt();
    let mut w = PolyVec::inner_product(&s, &u);
    w.inverse_ntt_to_mont();
    w.subtract_from(&v);
    w.reduce();
    w.write_message(message);
}
