use crate::{ElGamalError, ElGamalPrivateKey, ElGamalPublicKey};
use core::fmt;
use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint, RandomBits};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `ElGamalEngine`：加密每次抽新的 k，密文是 γ = g^k 與 φ = y^k · m，各佔 p 的位元
/// 組數；解密算 m = γ^(p − 1 − x) · φ。
///
/// 區塊大小與 `tc_rsa` 一致，以 b 表示 p 的位元數：加密的輸入最多 `(b - 1) / 8` 位元組，
/// 輸出 `2 · ⌈b / 8⌉`；解密的輸入恰好 `2 · ⌈b / 8⌉`，輸出固定 `⌈b / 8⌉` 位元組、前面補零。
/// BC 解密只輸出 m 的有效位元組；固定長度才能直接套上 PKCS#1 與 OAEP。
///
/// 加密只需要亂數；解密也要給一個，但不會用到。
pub struct ElGamalEngine<R> {
    rng: R,
    state: Option<State>,
}

/// `init` 後的狀態：p 與它的 Montgomery 參數，以及方向所需的值。
struct State {
    bits: u32,
    p: PaddedBigUint,
    monty: PaddedMontyParams,
    mode: Mode,
}

enum Mode {
    /// 公鑰加密：g 與 y。
    Encrypt { g: PaddedBigUint, y: PaddedBigUint },
    /// 私鑰解密：先算好的指數 p − 1 − x，drop 時清除。
    Decrypt { exponent: Zeroizing<PaddedBigUint> },
}

impl<R> ElGamalEngine<R> {
    /// 尚未 `init`、以 `rng` 抽 k 的引擎。常數時間。
    pub fn new(rng: R) -> Self {
        Self { rng, state: None }
    }

    /// p 的位元組數 ⌈b / 8⌉。常數時間。
    fn half(state: &State) -> usize {
        (state.bits as usize).div_ceil(8)
    }
}

impl<R: Default> Default for ElGamalEngine<R> {
    fn default() -> Self {
        Self::new(R::default())
    }
}

impl<R> fmt::Display for ElGamalEngine<R> {
    /// 寫出 BC 的演算法名稱 `ElGamal`。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ElGamal")
    }
}

/// 檢查參數後，為 p 建好 Montgomery 參數。變動時間：參數是公開值。
fn prepare(
    params: &crate::ElGamalParameters,
) -> Result<(u32, PaddedBigUint, PaddedMontyParams), ElGamalError> {
    params.validate()?;
    let p = params.p().clone();
    let odd = Odd::new(p.clone()).ok_or(ElGamalError::InvalidKey)?;
    Ok((p.bits(), p, PaddedMontyParams::new(odd)))
}

impl<R> AsymmetricBlockCipherInit<ElGamalPublicKey> for ElGamalEngine<R> {
    type Error = ElGamalError;

    /// 以公鑰準備加密：方向必須是加密，參數要通過檢查，y 要在 `[2, p - 2]`；BC 不檢查 y，
    /// 但 y 為 1 或 p − 1 時密文會直接洩漏明文或其正負號。變動時間：公鑰是公開值。
    fn init(
        &mut self,
        direction: CipherDirection,
        key: &ElGamalPublicKey,
    ) -> Result<(), ElGamalError> {
        self.state = None;
        if direction != CipherDirection::Encrypt {
            return Err(ElGamalError::WrongKeyForDirection);
        }
        let (bits, p, monty) = prepare(key.params())?;
        let y = BigUint::from(key.y().clone());
        let p_big = BigUint::from(p.clone());
        if y < BigUint::from(2u8) || y > &p_big - 2u32 {
            return Err(ElGamalError::InvalidKey);
        }
        self.state = Some(State {
            bits,
            mode: Mode::Encrypt {
                g: key.params().g().clone(),
                y: key.y().clone(),
            },
            p,
            monty,
        });
        Ok(())
    }
}

impl<R> AsymmetricBlockCipherInit<ElGamalPrivateKey> for ElGamalEngine<R> {
    type Error = ElGamalError;

    /// 以私鑰準備解密：方向必須是解密，參數要通過檢查，x 不得大於 p − 2，並先算好指數
    /// p − 1 − x。對 x 是常數時間：比較與減法都不依 x 的值分支。
    fn init(
        &mut self,
        direction: CipherDirection,
        key: &ElGamalPrivateKey,
    ) -> Result<(), ElGamalError> {
        self.state = None;
        if direction != CipherDirection::Decrypt {
            return Err(ElGamalError::WrongKeyForDirection);
        }
        let (bits, p, monty) = prepare(key.params())?;
        let p_less_one = &p - 1u32;
        if *key.x() >= p_less_one {
            return Err(ElGamalError::InvalidKey);
        }
        let exponent = Zeroizing::new(&p_less_one - key.x());
        self.state = Some(State {
            bits,
            p,
            monty,
            mode: Mode::Decrypt { exponent },
        });
        Ok(())
    }
}

impl<R: CryptoRng> AsymmetricBlockCipher for ElGamalEngine<R> {
    type Error = ElGamalError;

    /// 加密時 `(b - 1) / 8`，解密時 `2 · ⌈b / 8⌉`；`init` 之前是 0。常數時間。
    fn input_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(state) => match state.mode {
                Mode::Encrypt { .. } => (state.bits as usize - 1) / 8,
                Mode::Decrypt { .. } => 2 * Self::half(state),
            },
        }
    }

    /// 加密時 `2 · ⌈b / 8⌉`，解密時 `⌈b / 8⌉`；`init` 之前是 0。常數時間。
    fn output_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(state) => match state.mode {
                Mode::Encrypt { .. } => 2 * Self::half(state),
                Mode::Decrypt { .. } => Self::half(state),
            },
        }
    }

    /// 加密或解密一個區塊，寫入 `output` 開頭並回傳寫入的位元組數。加密對 m 與 k、解密對
    /// x 與 m 都是常數時間；只有解密前對密文 γ、φ 的範圍檢查依值分支，它們是公開值。
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ElGamalError> {
        let state = self.state.as_ref().ok_or(ElGamalError::NotInitialized)?;
        let half = Self::half(state);
        match &state.mode {
            Mode::Encrypt { g, y } => {
                if input.len() > (state.bits as usize - 1) / 8 {
                    return Err(ElGamalError::InputTooLarge);
                }
                if output.len() < 2 * half {
                    return Err(ElGamalError::OutputTooShort);
                }
                encrypt(state, g, y, input, &mut self.rng, &mut output[..2 * half])?;
                Ok(2 * half)
            }
            Mode::Decrypt { exponent } => {
                if input.len() != 2 * half {
                    return Err(ElGamalError::InvalidCiphertextLength);
                }
                if output.len() < half {
                    return Err(ElGamalError::OutputTooShort);
                }
                decrypt(state, exponent, input, &mut output[..half])?;
                Ok(half)
            }
        }
    }
}

/// BC 的加密：k 是 b 位元的隨機值，為 0 或大於 p − 2 時重抽；γ = g^k mod p，
/// φ = y^k · m mod p。m 為 0 時回傳錯誤：BC 照樣加密，但 φ = 0 的密文解密時會被拒絕。
/// 對 m 與 k 是常數時間：取冪每個位元都做一次平方與一次乘法，被丟棄的 k 會清除，重抽的
/// 次數與留下的 k 無關；只有 m 是否為 0 會由錯誤透露。
fn encrypt(
    state: &State,
    g: &PaddedBigUint,
    y: &PaddedBigUint,
    input: &[u8],
    rng: &mut dyn CryptoRng,
    output: &mut [u8],
) -> Result<(), ElGamalError> {
    let half = output.len() / 2;
    let Ok(m) = PaddedBigUint::from_be(input);
    let m = Zeroizing::new(m);
    if m.bits() == 0 {
        return Err(ElGamalError::InputTooSmall);
    }
    let one = PaddedBigUint::from(1u8);
    let p_less_two = &state.p - 2u32;
    let k = loop {
        let mut k = PaddedBigUint::random_bits(rng, state.bits);
        if k >= one && k <= p_less_two {
            break Zeroizing::new(k);
        }
        k.zeroize();
    };

    let gamma = Zeroizing::new(PaddedMontyForm::new(g, &state.monty).pow(&k));
    let mut phi = Zeroizing::new(PaddedMontyForm::new(y, &state.monty).pow(&k));
    *phi *= &*Zeroizing::new(PaddedMontyForm::new(&m, &state.monty));
    write_be(&gamma.retrieve(), &mut output[..half]);
    write_be(&Zeroizing::new(phi.retrieve()), &mut output[half..]);
    Ok(())
}

/// BC 的解密：γ、φ 都要在 `[2, p - 2]`，以防小子群攻擊；m = γ^(p − 1 − x) · φ mod p。
/// 取冪與乘法對 x 與 m 是常數時間；範圍檢查依值分支，但密文是公開值。
fn decrypt(
    state: &State,
    exponent: &PaddedBigUint,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ElGamalError> {
    let half = output.len();
    let Ok(gamma) = PaddedBigUint::from_be(&input[..half]);
    let Ok(phi) = PaddedBigUint::from_be(&input[half..]);
    let p = BigUint::from(state.p.clone());
    let lowest = BigUint::from(2u8);
    let highest = &p - 2u32;
    for value in [&gamma, &phi] {
        let value = BigUint::from(value.clone());
        if value < lowest || value > highest {
            return Err(ElGamalError::WeakCiphertext);
        }
    }

    let mut m = Zeroizing::new(PaddedMontyForm::new(&gamma, &state.monty).pow(exponent));
    *m *= &PaddedMontyForm::new(&phi, &state.monty);
    write_be(&Zeroizing::new(m.retrieve()), output);
    Ok(())
}

/// `value` 以大端序寫滿 `output`，前面補零；value 必須放得下。對值是常數時間：只依寬度
/// 決定讀寫的位置。
fn write_be(value: &PaddedBigUint, output: &mut [u8]) {
    let mut bytes = ArrayEncoding::<u8>::to_be(value);
    let length = output.len().min(bytes.len());
    output.fill(0);
    let start = output.len() - length;
    output[start..].copy_from_slice(&bytes[bytes.len() - length..]);
    bytes.zeroize();
}
