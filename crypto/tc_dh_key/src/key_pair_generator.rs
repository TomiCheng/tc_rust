use crate::math::naf_weight;
use crate::{DhError, DhKeyGenerationParams, DhParameters, DhPrivateKey, DhPublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{BigUint, PaddedBigUint, RandomBits, RandomRange};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroize;

/// BC 的 `DHKeyPairGenerator`（`DHBasicKeyPairGenerator` 在 BC 已標為過時，做同一件事）。
/// `init` 檢查參數並為 p 建好 Montgomery 參數，之後每對金鑰共用。
pub struct DhKeyPairGenerator<'a> {
    state: Option<(DhKeyGenerationParams<'a>, PaddedMontyParams)>,
}

impl DhKeyPairGenerator<'_> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }
}

impl Default for DhKeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<DhKeyGenerationParams<'a>> for DhKeyPairGenerator<'a> {
    type Error = DhError;

    /// 以 [`DhParameters::validate`] 檢查參數，並為 p 建好 Montgomery 參數。變動時間：
    /// 參數是公開值。
    fn init(&mut self, params: DhKeyGenerationParams<'a>) -> Result<(), DhError> {
        params.params.validate()?;
        let p = Odd::new(params.params.p().clone()).ok_or(DhError::InvalidModulus)?;
        self.state = Some((params, PaddedMontyParams::new(p)));
        Ok(())
    }
}

impl KeyPairGenerator for DhKeyPairGenerator<'_> {
    type PublicKey = DhPublicKey;
    type PrivateKey = DhPrivateKey;
    type Error = DhError;

    /// BC 的 `GenerateKeyPair`：x 由 [`private_value`] 取得，y = g^x mod p。對 x 是常數
    /// 時間，只有被丟棄的候選值多少會反映在時間上。
    fn generate_key_pair(&mut self) -> Result<(DhPublicKey, DhPrivateKey), DhError> {
        let (params, monty) = self.state.as_mut().ok_or(DhError::NotInitialized)?;
        let x = private_value(&params.params, params.rng);
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

    let m = params.m();
    let min = if m != 0 {
        let mut min = BigUint::from(0u8);
        min.set_bit(m - 1, true);
        PaddedBigUint::from(min)
    } else {
        PaddedBigUint::from(2u8)
    };
    let order = params.q().unwrap_or(params.p());
    let max = order - 2u32;
    let min_weight = max.bits() >> 2;
    // `random_range` 取半開區間，BC 的 `CreateRandomInRange` 含上限。
    let high = &max + 1u32;
    loop {
        let mut x = PaddedBigUint::random_range(rng, &min, &high);
        if naf_weight(x.as_limbs()) >= min_weight {
            return x;
        }
        x.zeroize();
    }
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
