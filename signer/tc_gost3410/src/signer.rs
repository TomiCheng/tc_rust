use crate::Gost3410SignerError;
use alloc::vec;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit};
use tc_gost3410_key::{Gost3410Parameters, Gost3410PrivateKey, Gost3410PublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `Gost3410Signer`：GOST R 34.10-94。訊息（通常是 GOST R 34.11 的雜湊）讀成小端序
/// 整數 m；r = (a^k mod p) mod q，s = (k·m + x·r) mod q，k 由 `R` 抽取。
///
/// k 的讀法照 BC（q 的位元數的隨機位元組，大端序），但也排除 0；BC 只排除不小於 q 的值。
pub struct Gost3410Signer<R> {
    rng: R,
    state: Option<State>,
}

/// `init` 收下的金鑰與 p、q 的 Montgomery 參數。
struct State {
    key: Key,
    p: PaddedMontyParams,
    q: PaddedMontyParams,
}

/// 簽章用的私鑰或驗證用的公鑰。
enum Key {
    Signing(Gost3410PrivateKey),
    Verifying(Gost3410PublicKey),
}

impl<R> Gost3410Signer<R> {
    /// 以 `rng` 抽 k、尚未 `init` 的簽章器。常數時間。
    pub fn new(rng: R) -> Self {
        Self { rng, state: None }
    }

    /// 為 p 與 q 建好 Montgomery 參數並收下金鑰。變動時間：只依公開的參數。
    fn init_key(
        &mut self,
        params: &Gost3410Parameters,
        key: Key,
    ) -> Result<(), Gost3410SignerError> {
        let odd = |value: &PaddedBigUint| {
            Odd::new(value.clone()).expect("validate checked that p and q are odd")
        };
        self.state = Some(State {
            key,
            p: PaddedMontyParams::new(odd(params.p())),
            q: PaddedMontyParams::new(odd(params.q())),
        });
        Ok(())
    }
}

impl<R> DsaInit<Gost3410PrivateKey> for Gost3410Signer<R> {
    type Error = Gost3410SignerError;

    /// 以 `Gost3410PrivateKey::validate` 檢查金鑰，保存它的複本（drop 時清除 x）。失敗時
    /// 維持未初始化。對 x 是常數時間：只透露是否通過；參數只依公開值檢查。
    fn init(&mut self, key: &Gost3410PrivateKey) -> Result<(), Gost3410SignerError> {
        self.state = None;
        key.validate().map_err(Gost3410SignerError::InvalidKey)?;
        self.init_key(key.params(), Key::Signing(key.clone()))
    }
}

impl<R> DsaInit<Gost3410PublicKey> for Gost3410Signer<R> {
    type Error = Gost3410SignerError;

    /// 以 `Gost3410PublicKey::validate` 檢查金鑰。失敗時維持未初始化。變動時間：只能用於
    /// 公開值，金鑰是公開的。
    fn init(&mut self, key: &Gost3410PublicKey) -> Result<(), Gost3410SignerError> {
        self.state = None;
        key.validate().map_err(Gost3410SignerError::InvalidKey)?;
        self.init_key(key.params(), Key::Verifying(key.clone()))
    }
}

impl<R: CryptoRng> Dsa for Gost3410Signer<R> {
    type Integer = PaddedBigUint;
    type Error = Gost3410SignerError;

    /// q。`init` 之前呼叫會 panic。常數時間。
    fn order(&self) -> &PaddedBigUint {
        let state = self.state.as_ref().expect("the signer is initialized");
        state.q.modulus()
    }

    /// BC 的 `GenerateSignature`：r = (a^k mod p) mod q、s = (k·m + x·r) mod q。對 x 與 k
    /// 是常數時間：取冪、模乘與模加都不依它們分支；只有重抽 k 的次數反映在時間上，與最後的
    /// k 無關。
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), Gost3410SignerError> {
        let state = self
            .state
            .as_ref()
            .ok_or(Gost3410SignerError::NotInitialized)?;
        let Key::Signing(key) = &state.key else {
            return Err(Gost3410SignerError::NotForSigning);
        };
        let params = key.params();
        let q = params.q();
        let zero = PaddedBigUint::from(0u8);
        let k = loop {
            let mut k = random_bits(&mut self.rng, q.bits());
            if k != zero && &k < q {
                break Zeroizing::new(k);
            }
            k.zeroize();
        };
        let power = Zeroizing::new(PaddedMontyForm::new(params.a(), &state.p).pow(&k));
        let r = power.retrieve() % q;
        let m = PaddedMontyForm::new(&little_endian(message), &state.q);
        let mut sum = Zeroizing::new(PaddedMontyForm::new(&k, &state.q));
        *sum *= &m;
        let mut product = Zeroizing::new(PaddedMontyForm::new(key.x(), &state.q));
        *product *= &PaddedMontyForm::new(&r, &state.q);
        *sum += &*product;
        Ok((r, sum.retrieve()))
    }

    /// BC 的 `VerifySignature`：v = m^(q − 2)、z₁ = s·v、z₂ = (q − r)·v，
    /// (a^z₁ · y^z₂ mod p) mod q 要等於 r。r 與 s 要在 `[1, q − 1]`；BC 也接受 0。變動時間：
    /// 只能用於公開值，金鑰、訊息與簽章都是公開的。
    fn verify_signature(
        &self,
        message: &[u8],
        r: &PaddedBigUint,
        s: &PaddedBigUint,
    ) -> Result<bool, Gost3410SignerError> {
        let state = self
            .state
            .as_ref()
            .ok_or(Gost3410SignerError::NotInitialized)?;
        let Key::Verifying(key) = &state.key else {
            return Err(Gost3410SignerError::NotForVerifying);
        };
        let params = key.params();
        let q = params.q();
        let zero = PaddedBigUint::from(0u8);
        if *r == zero || *s == zero || r >= q || s >= q {
            return Ok(false);
        }
        let exponent = q.clone() - PaddedBigUint::from(2u8);
        let v = PaddedMontyForm::new(&little_endian(message), &state.q).pow_vartime(&exponent);
        let z1 = (PaddedMontyForm::new(s, &state.q) * &v).retrieve();
        let z2 = (-(PaddedMontyForm::new(r, &state.q) * &v)).retrieve();
        let left = PaddedMontyForm::new(params.a(), &state.p).pow_vartime(&z1);
        let right = PaddedMontyForm::new(key.y(), &state.p).pow_vartime(&z2);
        let u = (left * &right).retrieve() % q;
        Ok(u == *r)
    }
}

/// BC 的 `new BigInteger(bits, random)`：⌈bits / 8⌉ 個隨機位元組依大端序讀成整數，去掉
/// 最高位元組多出的位元；抽到的位元組用畢清除。常數時間：只依長度。
fn random_bits(rng: &mut dyn CryptoRng, bits: u32) -> PaddedBigUint {
    let length = bits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    if let Some(first) = bytes.first_mut() {
        *first &= 0xFF >> (length as u32 * 8 - bits);
    }
    let Ok(value) = PaddedBigUint::from_be(&bytes);
    bytes.zeroize();
    value
}

/// BC 的 `new BigInteger(1, message, bigEndian: false)`：訊息讀成小端序的無號整數。
/// 常數時間：只依長度。
fn little_endian(message: &[u8]) -> PaddedBigUint {
    let reversed: Vec<u8> = message.iter().rev().copied().collect();
    let Ok(value) = PaddedBigUint::from_be(&reversed);
    value
}
