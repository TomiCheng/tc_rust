use crate::MlKemParameters;
use crate::indcpa::{self, sha3};
use crate::poly::Poly;
use alloc::vec;
use tc_constant_time::{ConditionallySelectable, ConstantTimeEq};
use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_zeroize::Zeroizing;

/// BC 的 `GenerateKemKeyPairInternal`（FIPS 203 的 ML-KEM.KeyGen_internal）：由 seed = d ‖ z
/// 寫出 dk = dk_PKE ‖ ek ‖ H(ek) ‖ z。對 seed 是常數時間；Â 只依公開的 ρ。
pub(crate) fn generate_key_pair(params: &MlKemParameters, seed: &[u8; 64], dk: &mut [u8]) {
    let k = params.k();
    let (dk_pke, rest) = dk.split_at_mut(384 * k);
    let (ek, rest) = rest.split_at_mut(params.public_key_length());
    let (h, z) = rest.split_at_mut(32);
    indcpa::generate_key_pair(params, &seed[..32], dk_pke, ek);
    sha3(256, &[ek], h);
    z.copy_from_slice(&seed[32..]);
}

/// BC 的 `KemEncrypt`（ML-KEM.Encaps_internal）：(K, r) = G(m ‖ H(ek))，c = K-PKE.Encrypt(ek,
/// m, r)，共享秘密是 K。對 m、K 與 r 是常數時間。
pub(crate) fn encapsulate(
    params: &MlKemParameters,
    ek: &[u8],
    message: &[u8; 32],
    ciphertext: &mut [u8],
    secret: &mut [u8],
) {
    let mut h = [0u8; 32];
    sha3(256, &[ek], &mut h);
    let mut kr = Zeroizing::new([0u8; 64]);
    sha3(512, &[message, &h], &mut kr[..]);
    indcpa::encrypt(params, ek, message, &kr[32..], ciphertext);
    secret.copy_from_slice(&kr[..32]);
}

/// BC 的 `KemDecrypt`（ML-KEM.Decaps_internal）：m′ = K-PKE.Decrypt(dk_PKE, c)，
/// (K′, r′) = G(m′ ‖ h)，重新加密 c′；c′ = c 時共享秘密是 K′，否則是 J(z ‖ c) 的隱式拒絕。
/// 常數時間：密文的比較與兩個秘密的選擇都不分支，失敗與否不由時間透露。
pub(crate) fn decapsulate(
    params: &MlKemParameters,
    dk: &[u8],
    ciphertext: &[u8],
    secret: &mut [u8],
) {
    let k = params.k();
    let dk_pke = &dk[..384 * k];
    let ek = &dk[384 * k..384 * k + params.public_key_length()];
    let h = &dk[dk.len() - 64..dk.len() - 32];
    let z = &dk[dk.len() - 32..];

    let mut message = Zeroizing::new([0u8; 32]);
    indcpa::decrypt(params, ciphertext, dk_pke, &mut message);
    let mut kr = Zeroizing::new([0u8; 64]);
    sha3(512, &[&message[..], h], &mut kr[..]);
    let mut again = Zeroizing::new(vec![0u8; ciphertext.len()]);
    indcpa::encrypt(params, ek, &message[..], &kr[32..], &mut again);
    let equal = again.ct_eq(ciphertext);

    let mut rejection = Zeroizing::new([0u8; 32]);
    let mut xof = ShakeDigest::new(256);
    xof.update(z);
    xof.update(ciphertext);
    xof.output_final(&mut rejection[..]);

    let mut accepted = Zeroizing::new([0u8; 32]);
    accepted.copy_from_slice(&kr[..32]);
    let chosen = Zeroizing::new(<[u8; 32]>::conditional_select(&rejection, &accepted, equal));
    secret.copy_from_slice(&chosen[..]);
}

/// BC 的 `CheckEncapKeyModulus`（FIPS 203 7.2 的模數檢查）：ek 的每個係數都小於 q。變動
/// 時間：只能用於公開值。
pub(crate) fn check_encapsulation_key(params: &MlKemParameters, ek: &[u8]) -> bool {
    ek[..384 * params.k()]
        .chunks_exact(384)
        .all(Poly::check_modulus)
}

/// BC 的 `CheckDecapKeyHash`（FIPS 203 7.3 的雜湊檢查）：dk 裡的 H(ek) 要等於重算的值。
/// 常數時間：以常數時間比較，只透露是否通過。
pub(crate) fn check_decapsulation_key(params: &MlKemParameters, dk: &[u8]) -> bool {
    let k = params.k();
    let ek = &dk[384 * k..384 * k + params.public_key_length()];
    let mut h = [0u8; 32];
    sha3(256, &[ek], &mut h);
    h[..].ct_eq(&dk[dk.len() - 64..dk.len() - 32]).unwrap_u8() == 1
}
