use crate::{NaccacheSternError, NaccacheSternPrivateKey, NaccacheSternPublicKey};
use alloc::vec::Vec;
use core::fmt;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_modular::{ModAdd, ModMul, NonZero, Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `NaccacheSternEngine`：加密 c = gᵐ mod n；解密對每個小質數 pᵢ 算 c^(φ/pᵢ)，在表
/// 中找出 m mod pᵢ，再以中國餘數定理組回 m。不需要亂數，加密是確定性的。
///
/// 區塊大小以 b 表示 n 的位元數、s 表示 σ 的位元數：加密的輸入最多 `(s + 7) / 8 - 1`
/// 位元組，保證小於 σ，輸出 `b / 8 + 1`；解密的輸入恰好 `b / 8 + 1`，輸出固定
/// `⌈s / 8⌉` 位元組、前面補零。BC 解密輸出有號的 `ToByteArray`，長度不定。
///
/// BC 以 `IndexOf` 查表，找到就停，花費的時間透露明文；這裡每張表都掃完，以常數時間
/// 比較與選取。建表時以 g^(φ/pᵢ) 連乘取代 BC 的逐項取冪，結果相同。
#[derive(Default)]
pub struct NaccacheSternEngine {
    state: Option<State>,
}

/// `init` 後的狀態。
struct State {
    n: PaddedBigUint,
    n_bits: u32,
    sigma_bits: u32,
    g: PaddedBigUint,
    monty: PaddedMontyParams,
    decryption: Option<Decryption>,
}

/// 解密用的預先計算：每個小質數的指數、查表與 CRT 權重，以及 σ。
struct Decryption {
    primes: Vec<PrimeTable>,
    sigma: NonZero<PaddedBigUint>,
}

struct PrimeTable {
    /// φ / pᵢ，秘密。
    exponent: PaddedBigUint,
    /// g^(j·φ/pᵢ) mod n，j = 0, 1, …, pᵢ − 1，秘密。
    table: Vec<PaddedBigUint>,
    /// CRT 權重 bᵢ·(bᵢ⁻¹ mod pᵢ) mod σ，bᵢ = σ / pᵢ，公開。
    weight: PaddedBigUint,
}

impl Drop for Decryption {
    /// 清除指數與查表。常數時間。
    fn drop(&mut self) {
        for prime in &mut self.primes {
            prime.exponent.zeroize();
            for entry in &mut prime.table {
                entry.zeroize();
            }
        }
    }
}

impl NaccacheSternEngine {
    /// 尚未 `init` 的引擎。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }

    /// BC 的 `AddCryptedBlocks`：兩段密文相乘 mod n，解密後是兩個明文的和 mod σ。結果寫入
    /// `output` 開頭並回傳長度 `b / 8 + 1`。變動時間：只用於公開的密文。
    pub fn add_crypted_blocks(
        &self,
        block1: &[u8],
        block2: &[u8],
        output: &mut [u8],
    ) -> Result<usize, NaccacheSternError> {
        let state = self
            .state
            .as_ref()
            .ok_or(NaccacheSternError::NotInitialized)?;
        let length = state.n_bits as usize / 8 + 1;
        if block1.len() > length || block2.len() > length {
            return Err(NaccacheSternError::InvalidCiphertextLength);
        }
        if output.len() < length {
            return Err(NaccacheSternError::OutputTooShort);
        }
        let Ok(c1) = PaddedBigUint::from_be(block1);
        let Ok(c2) = PaddedBigUint::from_be(block2);
        let modulus = NonZero::new(state.n.clone()).expect("n is above 2");
        let product = c1.mod_mul(&c2, &modulus);
        write_be(&product, &mut output[..length]);
        Ok(length)
    }
}

impl fmt::Display for NaccacheSternEngine {
    /// 寫出 BC 的演算法名稱 `NaccacheStern`。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NaccacheStern")
    }
}

/// 檢查 n 是大於 2 的奇數，並為它建好 Montgomery 參數。變動時間：n 是公開值。
fn public_state(key: &NaccacheSternPublicKey) -> Result<State, NaccacheSternError> {
    let n = key.n().clone();
    if !n.bit(0) || n <= PaddedBigUint::from(2u8) {
        return Err(NaccacheSternError::InvalidKey);
    }
    let odd = Odd::new(n.clone()).ok_or(NaccacheSternError::InvalidKey)?;
    Ok(State {
        n_bits: n.bits(),
        sigma_bits: key.lower_sigma_bound(),
        g: key.g().clone(),
        monty: PaddedMontyParams::new(odd),
        n,
        decryption: None,
    })
}

impl AsymmetricBlockCipherInit<NaccacheSternPublicKey> for NaccacheSternEngine {
    type Error = NaccacheSternError;

    /// 以公鑰準備加密；解密需要私鑰。變動時間：公鑰是公開值。
    fn init(
        &mut self,
        direction: CipherDirection,
        key: &NaccacheSternPublicKey,
    ) -> Result<(), NaccacheSternError> {
        self.state = None;
        if direction != CipherDirection::Encrypt {
            return Err(NaccacheSternError::WrongKeyForDirection);
        }
        self.state = Some(public_state(key)?);
        Ok(())
    }
}

impl AsymmetricBlockCipherInit<NaccacheSternPrivateKey> for NaccacheSternEngine {
    type Error = NaccacheSternError;

    /// 以私鑰準備加密或解密，同 BC。解密時檢查每個小質數整除 φ(n)，並建好查表與 CRT
    /// 權重。對 φ(n) 是常數時間：除法、取冪與連乘都不依它的值分支；小質數的個數與大小
    /// 是公開的。
    fn init(
        &mut self,
        direction: CipherDirection,
        key: &NaccacheSternPrivateKey,
    ) -> Result<(), NaccacheSternError> {
        self.state = None;
        let mut state = public_state(key.public_key())?;
        if direction == CipherDirection::Decrypt {
            state.decryption = Some(decryption(&state, key)?);
        }
        self.state = Some(state);
        Ok(())
    }
}

/// 解密的預先計算：每個 pᵢ 要整除 φ，指數 φ / pᵢ，表 g^(j·φ/pᵢ) 以 g^(φ/pᵢ) 連乘而得，
/// CRT 權重以小整數算出。對 φ(n) 是常數時間；權重只依公開的小質數。
fn decryption(
    state: &State,
    key: &NaccacheSternPrivateKey,
) -> Result<Decryption, NaccacheSternError> {
    let primes = key.small_primes();
    if primes.is_empty() || primes.iter().any(|&p| p < 2) {
        return Err(NaccacheSternError::InvalidKey);
    }
    let zero = PaddedBigUint::from(0u8);
    let divides = primes.iter().fold(Choice::from_lsb(1), |all, &p| {
        all & (key.phi_n() % p).ct_eq(&zero)
    });
    if divides.unwrap_u8() == 0 {
        return Err(NaccacheSternError::InvalidKey);
    }

    let sigma = primes
        .iter()
        .fold(BigUint::from(1u8), |sigma, &p| sigma * BigUint::from(p));
    let one = PaddedMontyForm::new(&PaddedBigUint::from(1u8), &state.monty);
    let g = PaddedMontyForm::new(&state.g, &state.monty);
    let mut tables = Vec::with_capacity(primes.len());
    for &p in primes {
        let exponent = key.phi_n() / p;
        let base = Zeroizing::new(g.pow(&exponent));
        let mut power = Zeroizing::new(one.clone());
        let mut table = Vec::with_capacity(p as usize);
        for _ in 0..p {
            table.push(power.retrieve());
            *power *= &*base;
        }
        tables.push(PrimeTable {
            exponent,
            table,
            weight: crt_weight(&sigma, p),
        });
    }
    Ok(Decryption {
        primes: tables,
        sigma: NonZero::new(PaddedBigUint::from(sigma)).expect("σ is a product of primes"),
    })
}

/// BC `ChineseRemainder` 的係數：bᵢ·(bᵢ⁻¹ mod pᵢ) mod σ，bᵢ = σ / pᵢ；pᵢ 是質數，反元素
/// 以費馬小定理算出。變動時間：只依公開的小質數。
fn crt_weight(sigma: &BigUint, p: u32) -> PaddedBigUint {
    let b = sigma / &BigUint::from(p);
    let b_mod_p = u64::from(rem_u32(&b, p));
    let p64 = u64::from(p);
    let (mut inverse, mut base, mut exponent) = (1u64, b_mod_p, p64 - 2);
    while exponent > 0 {
        if exponent & 1 == 1 {
            inverse = inverse * base % p64;
        }
        base = base * base % p64;
        exponent >>= 1;
    }
    PaddedBigUint::from((b * BigUint::from(inverse)) % sigma)
}

/// `value mod modulus`，由高位往低位逐 limb。變動時間：只用於公開值。
fn rem_u32(value: &BigUint, modulus: u32) -> u32 {
    let modulus = u128::from(modulus);
    let mut r = 0u128;
    for limb in value.as_limbs().iter().rev() {
        r = ((r << tc_bigint::Word::BITS) | u128::from(limb.to_word())) % modulus;
    }
    r as u32
}

impl AsymmetricBlockCipher for NaccacheSternEngine {
    type Error = NaccacheSternError;

    /// 加密時 `(s + 7) / 8 - 1`，解密時 `b / 8 + 1`；`init` 之前是 0。常數時間。
    fn input_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(state) if state.decryption.is_some() => state.n_bits as usize / 8 + 1,
            Some(state) => (state.sigma_bits as usize).div_ceil(8) - 1,
        }
    }

    /// 加密時 `b / 8 + 1`，解密時 `⌈s / 8⌉`；`init` 之前是 0。常數時間。
    fn output_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(state) if state.decryption.is_some() => (state.sigma_bits as usize).div_ceil(8),
            Some(state) => state.n_bits as usize / 8 + 1,
        }
    }

    /// 加密或解密一個區塊，寫入 `output` 開頭並回傳寫入的位元組數。加密對 m 是常數時間；
    /// 解密對 φ(n) 與 m 是常數時間：取冪不依值分支，每張表都整張掃完，比較與選取都不
    /// 分支，CRT 以模加與模乘組合；只有密文是否屬於這把金鑰由錯誤透露。
    fn process_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, NaccacheSternError> {
        let state = self
            .state
            .as_ref()
            .ok_or(NaccacheSternError::NotInitialized)?;
        let input_size = self.input_block_size();
        let output_size = self.output_block_size();
        match &state.decryption {
            None => {
                if input.len() > input_size {
                    return Err(NaccacheSternError::InputTooLarge);
                }
                if output.len() < output_size {
                    return Err(NaccacheSternError::OutputTooShort);
                }
                encrypt(state, input, &mut output[..output_size]);
            }
            Some(decryption) => {
                if input.len() != input_size {
                    return Err(NaccacheSternError::InvalidCiphertextLength);
                }
                if output.len() < output_size {
                    return Err(NaccacheSternError::OutputTooShort);
                }
                decrypt(state, decryption, input, &mut output[..output_size])?;
            }
        }
        Ok(output_size)
    }
}

/// BC 的 `Encrypt`：gᵐ mod n。對 m 是常數時間：取冪每個位元都做一次平方與一次乘法。
fn encrypt(state: &State, input: &[u8], output: &mut [u8]) {
    let Ok(m) = PaddedBigUint::from_be(input);
    let m = Zeroizing::new(m);
    let c = PaddedMontyForm::new(&state.g, &state.monty)
        .pow(&m)
        .retrieve();
    write_be(&c, output);
}

/// BC 的解密：c 先化約到 n 以下；每個 pᵢ 算 c^(φ/pᵢ)，與整張表逐格以常數時間比較，選出
/// 相符的 j = m mod pᵢ；再以 m = Σ jᵢ·wᵢ mod σ 組回。對 φ(n) 與 m 是常數時間；查不到時
/// 回傳錯誤，只透露密文不屬於這把金鑰。
fn decrypt(
    state: &State,
    decryption: &Decryption,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), NaccacheSternError> {
    let Ok(c) = PaddedBigUint::from_be(input);
    let c = &c % &state.n;
    let form = PaddedMontyForm::new(&c, &state.monty);
    let mut found_all = Choice::from_lsb(1);
    let mut m = Zeroizing::new(PaddedBigUint::from(0u8));
    for prime in &decryption.primes {
        let value = Zeroizing::new(form.pow(&prime.exponent).retrieve());
        let mut index = 0u32;
        let mut found = Choice::from_lsb(0);
        for (j, entry) in prime.table.iter().enumerate() {
            let equal = value.ct_eq(entry);
            index = u32::conditional_select(&index, &(j as u32), equal);
            found = found | equal;
        }
        found_all = found_all & found;
        let term = Zeroizing::new(
            prime
                .weight
                .mod_mul(&PaddedBigUint::from(index), &decryption.sigma),
        );
        *m = m.mod_add(&term, &decryption.sigma);
        index.zeroize();
    }
    if found_all.unwrap_u8() == 0 {
        return Err(NaccacheSternError::LookupFailed);
    }
    write_be(&m, output);
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
