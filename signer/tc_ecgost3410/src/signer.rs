use crate::EcGost3410Error;
use alloc::vec;
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit, DsaKCalculator};
use tc_ec_core::multiplier::{BaseMultiplier, PerCall};
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// BC 的 `ECGost3410Signer`：GOST R 34.10-2001／2012 的 EC 簽章，k 由計算器 `K` 取得。訊息
/// （通常是 GOST R 34.11 的雜湊）讀成小端序整數 e；r = (k·G).x mod n，
/// s = (k·e + d·r) mod n。以常數時間曲線上的金鑰初始化，d 與 k 才不會外洩。
///
/// BC 以 n 的位元數抽 k、只排除 0；這裡由計算器取 `[1, n − 1]` 的 k，例如 `tc_dsa` 的
/// `RandomDsaKCalculator`，結果相同而分布均勻。每次 `init` 為 G（驗證時也為 Q）建一個
/// `M`，預設的 [`PerCall`] 照曲線的方式乘點。
pub struct EcGost3410Signer<C: Curve<Scalar = PaddedBigUint>, K, M = PerCall<C>> {
    k_calculator: K,
    state: Option<State<C, M>>,
}

/// `init` 收下的金鑰與 n 的 Montgomery 參數。
struct State<C: Curve<Scalar = PaddedBigUint>, M> {
    key: Key<C, M>,
    params: PaddedMontyParams,
}

/// 簽章用的私鑰，或驗證用的兩個乘點器。
enum Key<C: Curve<Scalar = PaddedBigUint>, M> {
    Signing { key: EcPrivateKey<C>, g: M },
    Verifying { g: M, q: M },
}

impl<C: Curve<Scalar = PaddedBigUint>, K> EcGost3410Signer<C, K> {
    /// 由 `k_calculator` 取 k、照曲線的方式乘點，尚未 `init`。常數時間。
    pub const fn new(k_calculator: K) -> Self {
        Self::with_multiplier(k_calculator)
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> EcGost3410Signer<C, K, M> {
    /// 由 `k_calculator` 取 k、以 `M` 乘點，尚未 `init`。常數時間。
    pub const fn with_multiplier(k_calculator: K) -> Self {
        Self {
            k_calculator,
            state: None,
        }
    }

    /// 以 G 的曲線的階建好 Montgomery 參數並收下金鑰；階不存在或為偶數時回傳錯誤。變動
    /// 時間：只依公開的 n。
    fn init_key(
        &mut self,
        g: &C::Point,
        key: impl FnOnce() -> Key<C, M>,
    ) -> Result<(), EcGost3410Error> {
        self.state = None;
        let n = g
            .curve()
            .order()
            .cloned()
            .ok_or(EcGost3410Error::MissingOrder)?;
        let n = Odd::new(n).ok_or(EcGost3410Error::MissingOrder)?;
        self.state = Some(State {
            key: key(),
            params: PaddedMontyParams::new(n),
        });
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> DsaInit<EcPrivateKey<C>>
    for EcGost3410Signer<C, K, M>
{
    type Error = EcGost3410Error;

    /// 保存簽章用私鑰的複本（drop 時清除 d），並為 G 建 `M`。曲線沒有奇數階時回傳錯誤。
    /// 變動時間：只依公開的 n 與 G。
    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), EcGost3410Error> {
        self.init_key(key.g(), || Key::Signing {
            key: key.clone(),
            g: M::new(key.g().clone()),
        })
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> DsaInit<EcPublicKey<C>>
    for EcGost3410Signer<C, K, M>
{
    type Error = EcGost3410Error;

    /// 為 G 與 Q 各建一個 `M`。曲線沒有奇數階時回傳錯誤。變動時間：只能用於公開值，金鑰
    /// 是公開的。
    fn init(&mut self, key: &EcPublicKey<C>) -> Result<(), EcGost3410Error> {
        self.init_key(key.g(), || Key::Verifying {
            g: M::new(key.g().clone()),
            q: M::new(key.q().clone()),
        })
    }
}

impl<C, K, M> Dsa for EcGost3410Signer<C, K, M>
where
    C: Curve<Scalar = PaddedBigUint>,
    K: DsaKCalculator<PaddedBigUint>,
    M: BaseMultiplier<C>,
{
    type Integer = PaddedBigUint;
    type Error = EcGost3410Error;

    /// n。`init` 之前呼叫會 panic。常數時間。
    fn order(&self) -> &PaddedBigUint {
        let state = self.state.as_ref().expect("the signer is initialized");
        state.params.modulus()
    }

    /// BC 的 `GenerateSignature`：r = (k·G).x mod n、s = (k·e + d·r) mod n，任一為 0 時
    /// 重取 k。對 d 與 k 的常數時間程度同 `M` 的乘點；模運算是常數時間。
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), EcGost3410Error> {
        let state = self.state.as_ref().ok_or(EcGost3410Error::NotInitialized)?;
        let Key::Signing { key, g } = &state.key else {
            return Err(EcGost3410Error::NotForSigning);
        };
        let params = &state.params;
        let n = params.modulus();
        let e = PaddedMontyForm::new(&little_endian(message), params);
        let d = Zeroizing::new(PaddedMontyForm::new(key.d(), params));
        let zero = PaddedBigUint::from(0u8);

        self.k_calculator.init(n, key.d(), message);
        loop {
            let k = Zeroizing::new(self.k_calculator.next_k());
            let x = g
                .multiply(&k)
                .x()
                .expect("k·G is finite for k in [1, n − 1]");
            let r = field_to_integer(&x) % n;
            if r == zero {
                continue;
            }
            let mut sum = Zeroizing::new(PaddedMontyForm::new(&k, params));
            *sum *= &e;
            let mut product = Zeroizing::new(PaddedMontyForm::new(&r, params));
            *product *= &*d;
            *sum += &*product;
            let s = sum.retrieve();
            if s != zero {
                return Ok((r, s));
            }
        }
    }

    /// BC 的 `VerifySignature`：r 與 s 要在 `[1, n − 1]`；v = e⁻¹、z₁ = s·v、z₂ = −r·v，
    /// (z₁·G + z₂·Q).x mod n 要等於 r。e 沒有反元素（e ≡ 0 mod n）時視為不符，BC 會丟出
    /// 例外。變動時間：只能用於公開值，金鑰、訊息與簽章都是公開的。
    fn verify_signature(
        &self,
        message: &[u8],
        r: &PaddedBigUint,
        s: &PaddedBigUint,
    ) -> Result<bool, EcGost3410Error> {
        let state = self.state.as_ref().ok_or(EcGost3410Error::NotInitialized)?;
        let Key::Verifying { g, q } = &state.key else {
            return Err(EcGost3410Error::NotForVerifying);
        };
        let params = &state.params;
        let n = params.modulus();
        let zero = PaddedBigUint::from(0u8);
        if *r == zero || *s == zero || r >= n || s >= n {
            return Ok(false);
        }
        let Some(v) = PaddedMontyForm::new(&little_endian(message), params).invert() else {
            return Ok(false);
        };
        let z1 = (PaddedMontyForm::new(s, params) * &v).retrieve();
        let z2 = (-(PaddedMontyForm::new(r, params) * &v)).retrieve();
        let point = g.multiply(&z1).add(&q.multiply(&z2));
        let Some(x) = point.x() else {
            return Ok(false);
        };
        Ok(field_to_integer(&x) % n == *r)
    }
}

/// BC 的 `new BigInteger(1, message, bigEndian: false)`：訊息讀成小端序的無號整數。
/// 常數時間：只依長度。
fn little_endian(message: &[u8]) -> PaddedBigUint {
    let reversed: Vec<u8> = message.iter().rev().copied().collect();
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&reversed);
    value
}

/// 域元素依 SEC 1 編碼讀成的整數。常數時間：只依長度。
fn field_to_integer<F: FieldElement>(x: &F) -> PaddedBigUint {
    let mut bytes = Zeroizing::new(vec![0; x.encoded_length()]);
    x.encode_to(&mut bytes);
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    value
}
