use crate::DsaSignerError;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit, DsaKCalculator};
use tc_dsa_key::{DsaPrivateKey, DsaPublicKey};
use tc_modular::{ModAdd, ModInverse, ModMul, NonZero, Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// BC 的 `DsaSigner`：FIPS 186 的 DSA。r = (g^k mod p) mod q，s = k⁻¹ · (m + x·r) mod q，m 是
/// 雜湊的前 ⌊bits(q) / 8⌋ 個位元組。k 由 `K` 提供：亂數的 `RandomDsaKCalculator`，或 RFC 6979
/// 的 `HMacDsaKCalculator`。r 或 s 為零時另取 k，同 FIPS 186-4 4.6；BC 不重抽。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_dsa::{Dsa, DsaInit, HMacDsaKCalculator};
/// use tc_dsa_key::{
///     DsaKeyGenerationParams, DsaKeyPairGenerator, DsaParameterGenerationParams,
///     DsaParametersGenerator,
/// };
/// use tc_dsa_signer::DsaSigner;
/// use tc_sha::Sha256Digest;
///
/// // 參數由 FIPS 186-3 產生；實務上用公開的參數即可，不必每次產生。
/// let mut rng = rand::rng();
/// let mut generator = DsaParametersGenerator::with_digest(Sha256Digest::new());
/// generator.init_fips186_3(DsaParameterGenerationParams::new(2048, 256, 80, &mut rng))?;
/// let params = generator.generate_parameters()?;
///
/// let mut rng = rand::rng();
/// let mut keys = DsaKeyPairGenerator::new();
/// keys.init(DsaKeyGenerationParams::new(params, &mut rng))?;
/// let (public_key, private_key) = keys.generate_key_pair()?;
///
/// // 以 RFC 6979 的確定性 k 簽一則訊息的雜湊。
/// let hash = [0x42; 32];
/// let mut signer = DsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
/// signer.init(&private_key)?;
/// let (r, s) = signer.generate_signature(&hash)?;
///
/// let mut verifier = DsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
/// verifier.init(&public_key)?;
/// assert!(verifier.verify_signature(&hash, &r, &s)?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DsaSigner<K> {
    k_calculator: K,
    state: Option<State>,
}

/// `init` 收下的金鑰、p 的 Montgomery 參數與 q。
struct State {
    key: Key,
    monty: PaddedMontyParams,
    q: NonZero<PaddedBigUint>,
}

/// 簽章用的私鑰，或驗證用的公鑰。
enum Key {
    Private(DsaPrivateKey),
    Public(DsaPublicKey),
}

impl<K> DsaSigner<K> {
    /// 以 `k_calculator` 取 k、尚未 `init` 的簽章器。常數時間。
    pub fn new(k_calculator: K) -> Self {
        Self {
            k_calculator,
            state: None,
        }
    }

    /// 為 p 建好 Montgomery 參數，記下 q 與金鑰。變動時間：只依公開的參數。
    fn start(
        &mut self,
        key: Key,
        p: &PaddedBigUint,
        q: &PaddedBigUint,
    ) -> Result<(), DsaSignerError> {
        let p = Odd::new(p.clone()).ok_or(DsaSignerError::InvalidKey(
            tc_dsa_key::DsaError::InvalidModulus,
        ))?;
        let q = NonZero::new(q.clone()).ok_or(DsaSignerError::InvalidKey(
            tc_dsa_key::DsaError::InvalidOrder,
        ))?;
        self.state = Some(State {
            key,
            monty: PaddedMontyParams::new(p),
            q,
        });
        Ok(())
    }
}

/// BC 的 `CalculateE`：`message` 的前 ⌊bits(q) / 8⌋ 個位元組依大端序讀成整數。常數時間：只依
/// 長度。
fn calculate_e(q: &PaddedBigUint, message: &[u8]) -> PaddedBigUint {
    let length = message.len().min(q.bits() as usize / 8);
    let Ok(e) = PaddedBigUint::from_be(&message[..length]);
    e
}

impl<K> DsaInit<DsaPrivateKey> for DsaSigner<K> {
    type Error = DsaSignerError;

    /// 以 [`DsaPrivateKey::validate`] 檢查金鑰，保存複本（drop 時清除 x）。失敗時維持未
    /// 初始化。對 x 是常數時間：範圍檢查只透露是否通過；參數只依公開值檢查。
    fn init(&mut self, key: &DsaPrivateKey) -> Result<(), DsaSignerError> {
        self.state = None;
        key.validate().map_err(DsaSignerError::InvalidKey)?;
        let params = key.params();
        self.start(Key::Private(key.clone()), params.p(), params.q())
    }
}

impl<K> DsaInit<DsaPublicKey> for DsaSigner<K> {
    type Error = DsaSignerError;

    /// 以 [`DsaPublicKey::validate`] 檢查金鑰，保存複本。失敗時維持未初始化。變動時間：只能
    /// 用於公開值。
    fn init(&mut self, key: &DsaPublicKey) -> Result<(), DsaSignerError> {
        self.state = None;
        key.validate().map_err(DsaSignerError::InvalidKey)?;
        let params = key.params();
        self.start(Key::Public(key.clone()), params.p(), params.q())
    }
}

impl<K: DsaKCalculator<PaddedBigUint>> Dsa for DsaSigner<K> {
    type Integer = PaddedBigUint;
    type Error = DsaSignerError;

    /// 子群階 q。`init` 之前呼叫會 panic。常數時間。
    fn order(&self) -> &PaddedBigUint {
        &self.state.as_ref().expect("the signer is initialized").q
    }

    /// BC 的 `GenerateSignature`：k 由 k 計算器以 q、x 與 `message` 取得，r 或 s 為零時另取。
    /// 以公鑰初始化時回傳錯誤。對 x 與 k 是常數時間：取冪、模乘、模加與反元素都是常數時間；
    /// 只有另取 k 的次數反映在時間上，與最後的 k 無關。
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), DsaSignerError> {
        let state = self.state.as_ref().ok_or(DsaSignerError::NotInitialized)?;
        let Key::Private(key) = &state.key else {
            return Err(DsaSignerError::NotForSigning);
        };
        let q = &state.q;
        let zero = PaddedBigUint::from(0u8);
        let m = calculate_e(q, message) % &**q;
        let x = key.x();
        self.k_calculator.init(q, x, message);
        loop {
            let k = Zeroizing::new(self.k_calculator.next_k());
            let power =
                Zeroizing::new(PaddedMontyForm::new(key.params().g(), &state.monty).pow(&k));
            let r = power.retrieve() % &**q;
            if r == zero {
                continue;
            }
            let inverse = Zeroizing::new(k.mod_inverse(q).expect("k lies in [1, q - 1]"));
            let product = Zeroizing::new(x.mod_mul(&r, q));
            let sum = Zeroizing::new(product.mod_add(&m, q));
            let s = inverse.mod_mul(&sum, q);
            if s != zero {
                return Ok((r, s));
            }
        }
    }

    /// BC 的 `VerifySignature`：r 與 s 要在 `[1, q − 1]`，w = s⁻¹，
    /// v = (g^(m·w) · y^(r·w) mod p) mod q 要等於 r。以私鑰初始化時回傳錯誤。變動時間：只能
    /// 用於公開值，簽章與訊息都是公開的。
    fn verify_signature(
        &self,
        message: &[u8],
        r: &PaddedBigUint,
        s: &PaddedBigUint,
    ) -> Result<bool, DsaSignerError> {
        let state = self.state.as_ref().ok_or(DsaSignerError::NotInitialized)?;
        let Key::Public(key) = &state.key else {
            return Err(DsaSignerError::NotForVerifying);
        };
        let q = &state.q;
        let zero = PaddedBigUint::from(0u8);
        if *r == zero || r >= &**q || *s == zero || s >= &**q {
            return Ok(false);
        }
        let m = calculate_e(q, message);
        let Some(w) = s.mod_inverse(q) else {
            return Ok(false);
        };
        let u1 = m.mod_mul(&w, q);
        let u2 = r.mod_mul(&w, q);
        let mut v = PaddedMontyForm::new(key.params().g(), &state.monty).pow(&u1);
        v *= &PaddedMontyForm::new(key.y(), &state.monty).pow(&u2);
        Ok(v.retrieve() % &**q == *r)
    }
}
