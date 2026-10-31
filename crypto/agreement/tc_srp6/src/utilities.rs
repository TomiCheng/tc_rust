//! BC 的 `Srp6Utilities`：SRP-6a 各個值的算法，client、server 與驗證值產生器共用。
//!
//! 數值以 [`PaddedBigUint`] 表示；M1、M2 與工作階段金鑰是雜湊值，保留雜湊輸出的位元組，
//! 不像 BC 轉成整數而丟掉前導的零。

use crate::Srp6Error;
use alloc::vec;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, Limb, PaddedBigUint, RandomRange};
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_zeroize::{Zeroize, Zeroizing};

/// k = H(PAD(N) | PAD(g))。變動時間：只用於公開的群組。
pub fn calculate_k<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    g: &PaddedBigUint,
) -> PaddedBigUint {
    let length = padded_length(n);
    update_padded(digest, n, length);
    update_padded(digest, g, length);
    finish_number(digest)
}

/// u = H(PAD(A) | PAD(B))。A、B 要小於 N。變動時間：只用於公開值。
pub fn calculate_u<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    a: &PaddedBigUint,
    b: &PaddedBigUint,
) -> PaddedBigUint {
    let length = padded_length(n);
    update_padded(digest, a, length);
    update_padded(digest, b, length);
    finish_number(digest)
}

/// x = H(s | H(I | ":" | P))。BC 多收一個沒用到的 N，這裡省略。對密碼是常數時間，只要
/// 雜湊本身是；長度是公開的。中間的雜湊值會清除。
pub fn calculate_x<D: Digest + ?Sized>(
    digest: &mut D,
    salt: &[u8],
    identity: &[u8],
    password: &[u8],
) -> PaddedBigUint {
    let mut inner = Zeroizing::new(vec![0u8; digest.digest_size()]);
    digest.update(identity);
    digest.update_byte(b':');
    digest.update(password);
    digest.do_final(&mut inner);
    digest.update(salt);
    digest.update(&inner);
    finish_number(digest)
}

/// 私密值 a 或 b：在 `[2^(m - 1), N - 1]` 中均勻取得，m 是 256 與 N 位元數一半中較小者。
/// BC 多收沒用到的雜湊與 g，這裡省略。對抽到的值是常數時間；N 必須是公開的。
pub fn generate_private_value<R: CryptoRng + ?Sized>(
    n: &PaddedBigUint,
    rng: &mut R,
) -> PaddedBigUint {
    let min_bits = 256u32.min(n.bits() / 2);
    let mut min = zero(n.as_limbs().len());
    min.set_bit(min_bits - 1, true);
    // `random_range` 取半開區間，BC 的 `CreateRandomInRange` 含上限 N - 1。
    PaddedBigUint::random_range(rng, &min, n)
}

/// 對方的公開值除以 N 的餘數；餘數是 0 時拒絕。變動時間：只用於公開值。
pub fn validate_public_value(
    n: &PaddedBigUint,
    value: &PaddedBigUint,
) -> Result<PaddedBigUint, Srp6Error> {
    let value = value % n;
    if value == PaddedBigUint::from(0u8) {
        return Err(Srp6Error::InvalidPublicValue);
    }
    Ok(value)
}

/// client 的證明 M1 = H(PAD(A) | PAD(B) | PAD(S))。對 S 是常數時間，只要雜湊本身是。
pub fn calculate_m1<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    a: &PaddedBigUint,
    b: &PaddedBigUint,
    s: &PaddedBigUint,
) -> Vec<u8> {
    let length = padded_length(n);
    update_padded(digest, a, length);
    update_padded(digest, b, length);
    update_padded(digest, s, length);
    finish(digest)
}

/// server 的證明 M2 = H(PAD(A) | PAD(M1) | PAD(S))，M1 同其他值補到 N 的長度。對 S 是
/// 常數時間，只要雜湊本身是。
pub fn calculate_m2<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    a: &PaddedBigUint,
    m1: &[u8],
    s: &PaddedBigUint,
) -> Vec<u8> {
    let length = padded_length(n);
    update_padded(digest, a, length);
    update_padded_bytes(digest, m1, length);
    update_padded(digest, s, length);
    finish(digest)
}

/// 工作階段金鑰 K = H(PAD(S))。對 S 是常數時間，只要雜湊本身是。
pub fn calculate_key<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    s: &PaddedBigUint,
) -> Vec<u8> {
    update_padded(digest, s, padded_length(n));
    finish(digest)
}

/// 收到的證明是否等於算出的：同 BC 以整數比較，所以接受去掉前導零的編碼。比對是常數
/// 時間；只依公開的長度分支。
pub(crate) fn evidence_matches(expected: &[u8], received: &[u8]) -> bool {
    if received.len() > expected.len() {
        return false;
    }
    let mut padded = vec![0u8; expected.len()];
    padded[expected.len() - received.len()..].copy_from_slice(received);
    fixed_time_eq(expected, &padded)
}

/// 把 `value` 補到 `limbs` 個 limb 的寬度，值不變。常數時間。
pub(crate) fn widened(value: &PaddedBigUint, limbs: usize) -> PaddedBigUint {
    let mut wide = vec![Limb::new(0); limbs];
    wide[..value.as_limbs().len()].copy_from_slice(value.as_limbs());
    PaddedBigUint::new(wide.into_boxed_slice())
}

/// 寬度為 `limbs` 的 0。常數時間。
fn zero(limbs: usize) -> PaddedBigUint {
    PaddedBigUint::new(vec![Limb::new(0); limbs].into_boxed_slice())
}

/// N 的位元組數，PAD 補到的長度。變動時間：N 是公開的。
fn padded_length(n: &PaddedBigUint) -> usize {
    (n.bits() as usize).div_ceil(8)
}

/// `value` 以大端序補到 `length` 位元組後送進雜湊，BC 的 `AsUnsignedByteArray`；值放不下
/// 時 panic。對值是常數時間：只依寬度決定讀寫的位置，暫存會清除。
fn update_padded<D: Digest + ?Sized>(digest: &mut D, value: &PaddedBigUint, length: usize) {
    let mut bytes = ArrayEncoding::<u8>::to_be(value);
    update_padded_bytes(digest, &bytes, length);
    bytes.zeroize();
}

/// 大端序的 `bytes` 補零或去掉前導零到 `length` 位元組後送進雜湊；去掉的位元組不是零時
/// panic。對值是常數時間：只依長度決定讀寫的位置，暫存會清除。
fn update_padded_bytes<D: Digest + ?Sized>(digest: &mut D, bytes: &[u8], length: usize) {
    let mut padded = Zeroizing::new(vec![0u8; length]);
    if bytes.len() > length {
        let excess = bytes.len() - length;
        let high = bytes[..excess].iter().fold(0u8, |acc, &byte| acc | byte);
        assert!(high == 0, "the value is longer than N");
        padded.copy_from_slice(&bytes[excess..]);
    } else {
        padded[length - bytes.len()..].copy_from_slice(bytes);
    }
    digest.update(&padded);
}

/// 結束雜湊，回傳輸出的位元組。常數時間，只要雜湊本身是。
fn finish<D: Digest + ?Sized>(digest: &mut D) -> Vec<u8> {
    let mut output = vec![0u8; digest.digest_size()];
    digest.do_final(&mut output);
    output
}

/// 結束雜湊，以大端序的整數回傳，BC 的 `new BigInteger(1, output)`。常數時間，只要雜湊
/// 本身是；暫存會清除。
fn finish_number<D: Digest + ?Sized>(digest: &mut D) -> PaddedBigUint {
    let output = Zeroizing::new(finish(digest));
    let Ok(value) = PaddedBigUint::from_be(&output);
    value
}
