use crate::math::{naf_weight, random_bits};
use crate::{Gost3410Error, Gost3410KeyGenerationParams, Gost3410PrivateKey, Gost3410PublicKey};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

// BC 的 `minWeight`：x 的 NAF 至少要有的非零位數。
const MIN_WEIGHT: u32 = 64;

/// BC 的 `Gost3410KeyPairGenerator`：x 是 256 位元的隨機值，落在 `[1, q − 1]` 且 NAF 權重
/// 至少 64，y = a^x mod p。`init` 檢查參數並為 p 建好 Montgomery 參數。
pub struct Gost3410KeyPairGenerator<'a> {
    state: Option<(Gost3410KeyGenerationParams<'a>, PaddedMontyParams)>,
}

impl Gost3410KeyPairGenerator<'_> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }
}

impl Default for Gost3410KeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<Gost3410KeyGenerationParams<'a>> for Gost3410KeyPairGenerator<'a> {
    type Error = Gost3410Error;

    /// 以 [`Gost3410Parameters::validate`](crate::Gost3410Parameters::validate) 檢查參數，
    /// 並為 p 建好 Montgomery 參數。變動時間：參數是公開值。
    fn init(&mut self, params: Gost3410KeyGenerationParams<'a>) -> Result<(), Gost3410Error> {
        self.state = None;
        params.params.validate()?;
        let p = Odd::new(params.params.p().clone()).ok_or(Gost3410Error::InvalidModulus)?;
        self.state = Some((params, PaddedMontyParams::new(p)));
        Ok(())
    }
}

impl KeyPairGenerator for Gost3410KeyPairGenerator<'_> {
    type PublicKey = Gost3410PublicKey;
    type PrivateKey = Gost3410PrivateKey;
    type Error = Gost3410Error;

    /// BC 的 `GenerateKeyPair`：照 BC 讀取亂數（32 個位元組依大端序），丟棄不合格的候選值；
    /// y = a^x mod p。對 x 是常數時間：比較、NAF 權重與取冪都不依 x 分支，丟棄的候選值會
    /// 清除；只有重抽的次數反映在時間上，與最後的 x 無關。
    fn generate_key_pair(
        &mut self,
    ) -> Result<(Gost3410PublicKey, Gost3410PrivateKey), Gost3410Error> {
        let (params, monty) = self.state.as_mut().ok_or(Gost3410Error::NotInitialized)?;
        let q = params.params.q();
        let one = PaddedBigUint::from(1u8);
        let x = loop {
            let mut x = random_bits(params.rng, 256);
            if x >= one && &x < q && naf_weight(x.as_limbs()) >= MIN_WEIGHT {
                break x;
            }
            x.zeroize();
        };
        let power = Zeroizing::new(PaddedMontyForm::new(params.params.a(), monty).pow(&x));
        let y = power.retrieve();
        Ok((
            Gost3410PublicKey::new(y, params.params.clone()),
            Gost3410PrivateKey::new(x, params.params.clone()),
        ))
    }
}
