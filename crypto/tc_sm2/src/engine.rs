use crate::{Sm2Curve, Sm2Error};
use alloc::vec;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{PaddedBigUint, RandomBits};
use tc_digest::Digest;
use tc_ec_core::{FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_sm3::Sm3Digest;
use tc_zeroize::{Zeroize, Zeroizing};

/// 密文三段的排列，BC 的 `SM2Engine.Mode`。C1 是點 kG，C2 是加密後的訊息，C3 是雜湊。
/// GM/T 0003-2012 用 C1C3C2；BC 預設 C1C2C3，沿用舊版草案。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sm2Mode {
    /// C1 ‖ C2 ‖ C3。
    C1C2C3,
    /// C1 ‖ C3 ‖ C2。
    C1C3C2,
}

/// BC 的 `SM2Engine`：SM2 公鑰加密。加密抽隨機的 k，C1 = kG，以 kQ 的座標經 KDF 產生
/// 金鑰流與訊息互斥或得到 C2，C3 = H(x₂ ‖ M ‖ y₂)；解密以 d 算出 dC1 = kQ，反向做一次並
/// 核對 C3。雜湊預設是 SM3。
///
/// 密文長度隨訊息而變，不是固定區塊，所以同 BC 不實作 `AsymmetricBlockCipher`，而以
/// [`output_size`](Self::output_size) 與 [`process_block`](Self::process_block) 操作；
/// 初始化沿用 `tc_asym_cipher` 的 `AsymmetricBlockCipherInit`。
///
/// 加密需要亂數；解密也要給一個，但不會用到。
pub struct Sm2Engine<C: Sm2Curve, R, D = Sm3Digest> {
    digest: D,
    mode: Sm2Mode,
    rng: R,
    state: Option<State<C>>,
}

/// `init` 後的狀態：方向與它的金鑰。
enum State<C: Sm2Curve> {
    Encrypt(EcPublicKey<C>),
    Decrypt(EcPrivateKey<C>),
}

impl<C: Sm2Curve> State<C> {
    /// 金鑰的生成點 G。常數時間。
    fn g(&self) -> &C::Point {
        match self {
            Self::Encrypt(key) => key.g(),
            Self::Decrypt(key) => key.g(),
        }
    }
}

impl<C: Sm2Curve, R> Sm2Engine<C, R, Sm3Digest> {
    /// 以 SM3 為雜湊、以 `rng` 抽 k 的引擎，尚未 `init`。常數時間。
    pub fn new(mode: Sm2Mode, rng: R) -> Self {
        Self::with_digest(Sm3Digest::new(), mode, rng)
    }
}

impl<C: Sm2Curve, R, D: Digest + Clone> Sm2Engine<C, R, D> {
    /// 以 `digest` 為雜湊的引擎，同 BC 的 `SM2Engine(IDigest, Mode)`。常數時間。
    pub fn with_digest(digest: D, mode: Sm2Mode, rng: R) -> Self {
        Self {
            digest,
            mode,
            rng,
            state: None,
        }
    }

    /// 一個座標的位元組數，BC 的 `FieldElementEncodingLength`。常數時間。
    fn field_length(state: &State<C>) -> usize {
        state.g().curve().one().encoded_length()
    }

    /// 處理 `input_len` 位元組所需的輸出長度：加密時是 C1、C2、C3 的總長，解密時是 C2 的
    /// 長度，密文太短時是 0；`init` 之前是 0。BC 的 `GetOutputSize` 只算加密的長度。
    /// 常數時間。
    pub fn output_size(&self, input_len: usize) -> usize {
        let Some(state) = &self.state else {
            return 0;
        };
        let overhead = 1 + 2 * Self::field_length(state) + self.digest.digest_size();
        match state {
            State::Encrypt(_) => overhead + input_len,
            State::Decrypt(_) => input_len.saturating_sub(overhead),
        }
    }

    /// 加密或解密，寫入 `output` 開頭並回傳寫入的位元組數。加密對 k 與訊息是常數時間；
    /// 解密對 d 與訊息是常數時間，C3 以常數時間比對。只有解開公開的 C1 依值分支。
    pub fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Sm2Error>
    where
        R: CryptoRng,
    {
        let state = self.state.as_ref().ok_or(Sm2Error::NotInitialized)?;
        if input.is_empty() {
            return Err(Sm2Error::EmptyInput);
        }
        let field_length = Self::field_length(state);
        let digest_size = self.digest.digest_size();
        match state {
            State::Encrypt(key) => {
                let length = 1 + 2 * field_length + input.len() + digest_size;
                if output.len() < length {
                    return Err(Sm2Error::OutputTooShort);
                }
                encrypt(
                    key,
                    &self.digest,
                    self.mode,
                    field_length,
                    input,
                    &mut self.rng,
                    &mut output[..length],
                )?;
                Ok(length)
            }
            State::Decrypt(key) => {
                let c1_length = 1 + 2 * field_length;
                if input.len() < c1_length + digest_size {
                    return Err(Sm2Error::CiphertextTooShort);
                }
                let c2_length = input.len() - c1_length - digest_size;
                if output.len() < c2_length {
                    return Err(Sm2Error::OutputTooShort);
                }
                decrypt(
                    key,
                    &self.digest,
                    self.mode,
                    field_length,
                    input,
                    &mut output[..c2_length],
                )?;
                Ok(c2_length)
            }
        }
    }
}

impl<C: Sm2Curve, R, D> AsymmetricBlockCipherInit<EcPublicKey<C>> for Sm2Engine<C, R, D> {
    type Error = Sm2Error;

    /// 以公鑰準備加密：方向必須是加密，且 hQ 不是無窮遠點，同 BC。變動時間：公鑰是公開值。
    fn init(&mut self, direction: CipherDirection, key: &EcPublicKey<C>) -> Result<(), Sm2Error> {
        self.state = None;
        if direction != CipherDirection::Encrypt {
            return Err(Sm2Error::WrongKeyForDirection);
        }
        let curve = key.g().curve();
        curve.order().ok_or(Sm2Error::MissingOrder)?;
        if let Some(h) = curve.cofactor() {
            if C::multiply(key.q(), h).is_infinity() {
                return Err(Sm2Error::InvalidKey);
            }
        }
        self.state = Some(State::Encrypt(key.clone()));
        Ok(())
    }
}

impl<C: Sm2Curve, R, D> AsymmetricBlockCipherInit<EcPrivateKey<C>> for Sm2Engine<C, R, D> {
    type Error = Sm2Error;

    /// 以私鑰準備解密：方向必須是解密。私鑰的範圍已由 `EcPrivateKey::new` 檢查。常數時間。
    fn init(&mut self, direction: CipherDirection, key: &EcPrivateKey<C>) -> Result<(), Sm2Error> {
        self.state = None;
        if direction != CipherDirection::Decrypt {
            return Err(Sm2Error::WrongKeyForDirection);
        }
        self.state = Some(State::Decrypt(key.clone()));
        Ok(())
    }
}

/// BC 的 `Encrypt`：抽 k，算 kQ 並以 KDF 把訊息加密成 C2；金鑰流全為 0 時（C2 等於訊息）
/// 重抽，同 BC 的 `NotEncrypted`，但以常數時間比較。再寫出未壓縮的 C1 = kG 與
/// C3 = H(x₂ ‖ M ‖ y₂)。對 k 與訊息是常數時間：曲線是常數時間的，重抽只在金鑰流全為 0
/// 時發生，機率可以忽略。
fn encrypt<C: Sm2Curve, D: Digest + Clone>(
    key: &EcPublicKey<C>,
    digest: &D,
    mode: Sm2Mode,
    field_length: usize,
    input: &[u8],
    rng: &mut dyn CryptoRng,
    output: &mut [u8],
) -> Result<(), Sm2Error> {
    let n = key
        .g()
        .curve()
        .order()
        .ok_or(Sm2Error::MissingOrder)?
        .clone();
    let c1_length = 1 + 2 * field_length;
    let digest_size = digest.digest_size();
    let (c1, rest) = output.split_at_mut(c1_length);
    let (c2, c3) = match mode {
        Sm2Mode::C1C2C3 => {
            let (c2, c3) = rest.split_at_mut(input.len());
            (c2, c3)
        }
        Sm2Mode::C1C3C2 => {
            let (c3, c2) = rest.split_at_mut(digest_size);
            (c2, c3)
        }
    };

    let (k, x2, y2) = loop {
        let k = next_k(&n, rng);
        let (x2, y2) = coordinates::<C>(&C::multiply(key.q(), &k), field_length);
        c2.copy_from_slice(input);
        kdf(digest, &x2, &y2, c2);
        let changed = c2
            .iter()
            .zip(input)
            .fold(0u8, |changed, (c, m)| changed | (c ^ m));
        if changed != 0 {
            break (k, x2, y2);
        }
    };

    encode_uncompressed::<C>(&C::multiply(key.g(), &k), field_length, c1);
    let mut hash = digest.clone();
    hash.reset();
    hash.update(&x2);
    hash.update(input);
    hash.update(&y2);
    let mut tag = Zeroizing::new(vec![0u8; digest_size]);
    hash.do_final(&mut tag);
    c3.copy_from_slice(&tag);
    Ok(())
}

/// BC 的 `Decrypt`：解出 C1 並確認 hC1 不是無窮遠點，算 dC1，以 KDF 解出 C2，再以常數
/// 時間核對 C3；不符時清除已寫出的明文。解開 C1 依公開的值分支；dC1、KDF 與核對對 d 與
/// 訊息是常數時間，結果是否相符由錯誤透露。
fn decrypt<C: Sm2Curve, D: Digest + Clone>(
    key: &EcPrivateKey<C>,
    digest: &D,
    mode: Sm2Mode,
    field_length: usize,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), Sm2Error> {
    let c1_length = 1 + 2 * field_length;
    let digest_size = digest.digest_size();
    let curve = key.g().curve();
    let c1 = curve
        .decode_point(&input[..c1_length])
        .ok_or(Sm2Error::InvalidPoint)?;
    let h = curve
        .cofactor()
        .cloned()
        .unwrap_or(PaddedBigUint::from(1u8));
    if c1.is_infinity() || C::multiply(&c1, &h).is_infinity() {
        return Err(Sm2Error::InvalidPoint);
    }

    let (x2, y2) = coordinates::<C>(&C::multiply(&c1, key.d()), field_length);
    let (c2, c3) = match mode {
        Sm2Mode::C1C2C3 => {
            let rest = &input[c1_length..];
            rest.split_at(rest.len() - digest_size)
        }
        Sm2Mode::C1C3C2 => {
            let (c3, c2) = input[c1_length..].split_at(digest_size);
            (c2, c3)
        }
    };
    output.copy_from_slice(c2);
    kdf(digest, &x2, &y2, output);

    let mut hash = digest.clone();
    hash.reset();
    hash.update(&x2);
    hash.update(output);
    hash.update(&y2);
    let mut tag = Zeroizing::new(vec![0u8; digest_size]);
    hash.do_final(&mut tag);
    let difference = tag.iter().zip(c3).fold(0u8, |d, (a, b)| d | (a ^ b));
    if difference != 0 {
        output.zeroize();
        return Err(Sm2Error::InvalidCiphertext);
    }
    Ok(())
}

/// BC 的 `NextK`：n 位元數的隨機值，為 0 或不小於 n 時重抽。對 k 是常數時間：比較不依
/// k 分支，被丟棄的值會清除，重抽次數與留下的 k 無關。
fn next_k(n: &PaddedBigUint, rng: &mut dyn CryptoRng) -> Zeroizing<PaddedBigUint> {
    let one = PaddedBigUint::from(1u8);
    loop {
        let mut k = PaddedBigUint::random_bits(rng, n.bits());
        if k >= one && k < *n {
            return Zeroizing::new(k);
        }
        k.zeroize();
    }
}

/// 有限點的仿射座標，各編成 `field_length` 位元組，用畢清除。對座標是常數時間。
fn coordinates<C: Sm2Curve>(
    point: &C::Point,
    field_length: usize,
) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let point = point.normalize();
    let mut x = Zeroizing::new(vec![0u8; field_length]);
    let mut y = Zeroizing::new(vec![0u8; field_length]);
    point.x().expect("kQ and dC1 are finite").encode_to(&mut x);
    point.y().expect("kQ and dC1 are finite").encode_to(&mut y);
    (x, y)
}

/// 未壓縮的 SEC 1 編碼 04 ‖ x ‖ y，同 BC 的 `GetEncoded(false)`。對座標是常數時間。
fn encode_uncompressed<C: Sm2Curve>(point: &C::Point, field_length: usize, output: &mut [u8]) {
    let point = point.normalize();
    output[0] = 0x04;
    point
        .x()
        .expect("kG is finite")
        .encode_to(&mut output[1..1 + field_length]);
    point
        .y()
        .expect("kG is finite")
        .encode_to(&mut output[1 + field_length..]);
}

/// BC 的 `Kdf`：以 `x₂ ‖ y₂ ‖ ct` 的雜湊產生金鑰流，ct 是從 1 起算的大端序 32 位元計數，
/// 與 `data` 互斥或。先吸收 x₂ ‖ y₂ 再複製，同 BC 用 `IMemoable` 的作法。對座標與資料是
/// 常數時間。
fn kdf<D: Digest + Clone>(digest: &D, x2: &[u8], y2: &[u8], data: &mut [u8]) {
    let mut base = digest.clone();
    base.reset();
    base.update(x2);
    base.update(y2);
    let mut block = Zeroizing::new(vec![0u8; digest.digest_size()]);
    for (counter, chunk) in (1u32..).zip(data.chunks_mut(block.len())) {
        let mut round = base.clone();
        round.update(&counter.to_be_bytes());
        round.do_final(&mut block);
        for (byte, key) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= key;
        }
    }
}
