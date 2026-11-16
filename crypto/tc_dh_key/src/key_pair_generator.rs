use crate::math::naf_weight;
use crate::{DhError, DhKeyGenerationParams, DhParameters, DhPrivateKey, DhPublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{BigUint, PaddedBigUint, RandomBits, RandomRange};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroize;

/// BC 的 `DHKeyPairGenerator`（`DHBasicKeyPairGenerator` 在 BC 已標為過時，做同一件事）。
/// `init` 檢查參數並為 p 建好 Montgomery 參數，之後每對金鑰共用。
pub struct DhKeyPairGenerator<R> {
    rng: R,
    state: Option<(DhKeyGenerationParams, PaddedMontyParams)>,
}

impl<R> DhKeyPairGenerator<R> {
    /// 從 `rng` 取亂數、尚未 `init` 的產生器。常數時間。
    pub fn new(rng: R) -> Self {
        Self { rng, state: None }
    }
}

impl<R> KeyPairGeneratorInit<DhKeyGenerationParams> for DhKeyPairGenerator<R> {
    type Error = DhError;

    /// 以 [`DhParameters::validate`] 檢查參數，l 沒設定時再確認 x 的範圍不是空的（見
    /// [`private_range`]），並為 p 建好 Montgomery 參數。變動時間：參數是公開值。
    fn init(&mut self, params: &DhKeyGenerationParams) -> Result<(), DhError> {
        params.params.validate()?;
        if params.params.l() == 0 {
            private_range(&params.params)?;
        }
        let p = Odd::new(params.params.p().clone()).ok_or(DhError::InvalidModulus)?;
        self.state = Some((params.clone(), PaddedMontyParams::new(p)));
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for DhKeyPairGenerator<R> {
    type PublicKey = DhPublicKey;
    type PrivateKey = DhPrivateKey;
    type Error = DhError;

    /// BC 的 `GenerateKeyPair`：x 由 [`private_value`] 取得，y = g^x mod p。對 x 是常數
    /// 時間，只有被丟棄的候選值多少會反映在時間上。
    fn generate_key_pair(&mut self) -> Result<(DhPublicKey, DhPrivateKey), DhError> {
        let (params, monty) = self.state.as_ref().ok_or(DhError::NotInitialized)?;
        let x = private_value(&params.params, &mut self.rng);
        let y = public_value(monty, params.params.g(), &x);
        Ok((
            DhPublicKey::new(y, params.params.clone()),
            DhPrivateKey::new(x, params.params.clone()),
        ))
    }
}

/// BC `DHKeyGeneratorHelper.CalculatePrivate`。l 有設定時，x 是最高位為 1 的 l 位元隨機值；
/// 否則 x 在 `[2^(m - 1), q - 2]`（沒有 q 時用 p，m 為 0 時下限是 2）中均勻取得。兩者都
/// 要求 x 的 NAF 至少有上限位元數四分之一的非零位數，否則重抽，以免 x 過於稀疏。
///
/// 對 x 是常數時間：抽樣、比較與 NAF 權重都不依 x 的值分支，被丟棄的候選值會清除；
/// 只有重抽的次數反映在時間上，而它與最後的 x 無關。
fn private_value(params: &DhParameters, rng: &mut dyn CryptoRng) -> PaddedBigUint {
    let l = params.l();
    if l != 0 {
        let min_weight = l >> 2;
        loop {
            let mut x = PaddedBigUint::random_bits(rng, l);
            x.set_bit(l - 1, true);
            if naf_weight(x.as_limbs()) >= min_weight {
                return x;
            }
            x.zeroize();
        }
    }

    let (min, high) = private_range(params).expect("init checks the range");
    let min_weight = (&high - 1u32).bits() >> 2;
    loop {
        let mut x = PaddedBigUint::random_range(rng, &min, &high);
        if naf_weight(x.as_limbs()) >= min_weight {
            return x;
        }
        x.zeroize();
    }
}

/// l 沒設定時 x 的範圍：BC 的 `CreateRandomInRange(min, q - 2)` 含上限，這裡回傳半開的
/// `[min, q - 1)`，min 是 2^(m - 1)，m 為 0 時是 2，沒有 q 時用 p。範圍是空的時（q 太小，
/// 或 2^(m - 1) 超過 q - 2）回傳 [`DhError::InvalidPrivateValueLength`]，BC 是到產生時才丟出。
/// 變動時間：只用於公開值。
fn private_range(params: &DhParameters) -> Result<(PaddedBigUint, PaddedBigUint), DhError> {
    let m = params.m();
    let min = if m != 0 {
        let mut min = BigUint::from(0u8);
        min.set_bit(m - 1, true);
        PaddedBigUint::from(min)
    } else {
        PaddedBigUint::from(2u8)
    };
    let order = params.q().unwrap_or(params.p());
    if *order < &min + 2u32 {
        return Err(DhError::InvalidPrivateValueLength);
    }
    Ok((min, order - 1u32))
}

/// BC `DHKeyGeneratorHelper.CalculatePublic`：g^x mod p，以 Montgomery 形式取冪。對 x 是
/// 常數時間：每個位元都做一次平方與一次乘法；寬度是公開的。中間值會清除。
fn public_value(monty: &PaddedMontyParams, g: &PaddedBigUint, x: &PaddedBigUint) -> PaddedBigUint {
    let base = PaddedMontyForm::new(g, monty);
    let mut power = base.pow(x);
    let y = power.retrieve();
    power.zeroize();
    y
}
