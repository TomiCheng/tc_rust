use crate::EcnrError;
use alloc::vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit, DsaKCalculator};
use tc_ec_core::multiplier::{BaseMultiplier, PerCall};
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// BC 的 `ECNRSigner`，每個簽章的 k 由計算器 `K` 提供。以常數時間的曲線上的金鑰初始化，
/// d 與 k 才不會外洩。
///
/// BC 以 `ECKeyPairGenerator` 產生臨時金鑰對，這裡同 ECDSA 改由 k 計算器取 k。每次 `init`
/// 為 G（驗證時也為 Q）建一個 `M`，同一把金鑰簽或驗多次時共用它們的表。`M` 預設是
/// [`PerCall`]，照曲線的方式乘點。
pub struct EcnrSigner<C: Curve<Scalar = PaddedBigUint>, K, M = PerCall<C>> {
    k_calculator: K,
    state: Option<State<C, M>>,
}

/// `init` 收下的金鑰與 n 的 Montgomery 參數。
struct State<C: Curve<Scalar = PaddedBigUint>, M> {
    key: Key<C, M>,
    params: PaddedMontyParams,
}

/// 簽章時的私鑰與 G 的乘法器，或驗證時 G 與 Q 的乘法器。
enum Key<C: Curve<Scalar = PaddedBigUint>, M> {
    Signing { key: EcPrivateKey<C>, g: M },
    Verifying { g: M, q: M },
}

impl<C: Curve<Scalar = PaddedBigUint>, K> EcnrSigner<C, K> {
    /// 由 `k_calculator` 取 k、照曲線的方式乘點，尚未 `init`。常數時間。
    pub const fn new(k_calculator: K) -> Self {
        Self::with_multiplier(k_calculator)
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> EcnrSigner<C, K, M> {
    /// 由 `k_calculator` 取 k、以 `M` 乘點，尚未 `init`。常數時間。
    pub const fn with_multiplier(k_calculator: K) -> Self {
        Self {
            k_calculator,
            state: None,
        }
    }

    /// 以 G 的曲線的階建好 Montgomery 參數，收下金鑰。變動時間：只依公開的 n 與 G。
    fn init_key(&mut self, g: &C::Point, key: impl FnOnce() -> Key<C, M>) -> Result<(), EcnrError> {
        self.state = None;
        let n = g.curve().order().cloned().ok_or(EcnrError::MissingOrder)?;
        let n = Odd::new(n).ok_or(EcnrError::MissingOrder)?;
        self.state = Some(State {
            key: key(),
            params: PaddedMontyParams::new(n),
        });
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> DsaInit<EcPrivateKey<C>>
    for EcnrSigner<C, K, M>
{
    type Error = EcnrError;

    /// 保存簽章用私鑰的複本（drop 時清除 d），為 G 建一個 `M`。曲線沒有奇數的階時回傳
    /// 錯誤。變動時間：只依公開的 n 與 G。
    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), EcnrError> {
        self.init_key(key.g(), || Key::Signing {
            key: key.clone(),
            g: M::new(key.g().clone()),
        })
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> DsaInit<EcPublicKey<C>>
    for EcnrSigner<C, K, M>
{
    type Error = EcnrError;

    /// 為 G 與 Q 各建一個 `M`。曲線沒有奇數的階時回傳錯誤。變動時間：只能用於公開值，
    /// 金鑰是公開的。
    fn init(&mut self, key: &EcPublicKey<C>) -> Result<(), EcnrError> {
        self.init_key(key.g(), || Key::Verifying {
            g: M::new(key.g().clone()),
            q: M::new(key.q().clone()),
        })
    }
}

impl<C, K, M> Dsa for EcnrSigner<C, K, M>
where
    C: Curve<Scalar = PaddedBigUint>,
    K: DsaKCalculator<PaddedBigUint>,
    M: BaseMultiplier<C>,
{
    type Integer = PaddedBigUint;
    type Error = EcnrError;

    /// n。`init` 之前呼叫會 panic。常數時間。
    fn order(&self) -> &PaddedBigUint {
        let state = self.state.as_ref().expect("the signer is initialized");
        state.params.modulus()
    }

    /// BC 的 `GenerateSignature`，IEEE P1363 的 ECSP-NR：r = ((k·G).x + e) mod n，r 為零時
    /// 重取 k；s = (k − r·d) mod n。e 是整個 `message`，位元數不得多於 n。對 d 與 k 的
    /// 常數時間程度同 `M` 的乘點；模運算是常數時間的。
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), EcnrError> {
        let state = self.state.as_ref().ok_or(EcnrError::NotInitialized)?;
        let Key::Signing { key, g } = &state.key else {
            return Err(EcnrError::NotForSigning);
        };
        let params = &state.params;
        let n = params.modulus();
        let e = message_integer(n, message)?;
        let e = PaddedMontyForm::new(&(&e % n), params);
        let d = Zeroizing::new(PaddedMontyForm::new(key.d(), params));
        let zero = PaddedBigUint::from(0u8);

        self.k_calculator.init(n, key.d(), message);
        loop {
            let k = Zeroizing::new(self.k_calculator.next_k());
            let x = g
                .multiply(&k)
                .x()
                .expect("k·G is finite for k in [1, n − 1]");
            let mut sum = PaddedMontyForm::new(&(field_to_integer(&x) % n), params);
            sum += &e;
            let r = sum.retrieve();
            if r == zero {
                continue;
            }

            let rd = Zeroizing::new(PaddedMontyForm::new(&r, params) * &*d);
            let difference = Zeroizing::new(PaddedMontyForm::new(&k, params) - &*rd);
            return Ok((r, difference.retrieve()));
        }
    }

    /// BC 的 `VerifySignature`，IEEE P1363 的 ECVP-NR：P = s·G + r·Q，(r − P.x) mod n 是否
    /// 等於 e。r 不在 `[1, n − 1]`、s 不在 `[0, n − 1]`、P 是無窮遠點時回傳 `Ok(false)`；
    /// 訊息的位元數多於 n 時回傳錯誤，同 BC。變動時間：只能用於公開值，金鑰、訊息與簽章都是
    /// 公開的。
    fn verify_signature(
        &self,
        message: &[u8],
        r: &PaddedBigUint,
        s: &PaddedBigUint,
    ) -> Result<bool, EcnrError> {
        let state = self.state.as_ref().ok_or(EcnrError::NotInitialized)?;
        let Key::Verifying { g, q } = &state.key else {
            return Err(EcnrError::NotForVerifying);
        };
        let params = &state.params;
        let n = params.modulus();
        let e = message_integer(n, message)?;
        let zero = PaddedBigUint::from(0u8);
        if *r == zero || r >= n || s >= n {
            return Ok(false);
        }

        let point = g.multiply(s).add(&q.multiply(r));
        let Some(x) = point.x() else {
            return Ok(false);
        };
        let x = PaddedMontyForm::new(&(field_to_integer(&x) % n), params);
        let t = (PaddedMontyForm::new(r, params) - &x).retrieve();
        Ok(t == e)
    }
}

/// BC 的 `new BigInteger(1, message)`：整個訊息當成大端序的整數，位元數不得多於 n。
/// 變動時間：只能用於公開值，用於公開的雜湊。
fn message_integer(n: &PaddedBigUint, message: &[u8]) -> Result<PaddedBigUint, EcnrError> {
    let Ok(e) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(message);
    if e.bits() > n.bits() {
        return Err(EcnrError::InputTooLarge);
    }
    Ok(e)
}

/// 域元素以 SEC 1 編碼讀成的整數。對元素是常數時間。
fn field_to_integer<F: FieldElement>(x: &F) -> PaddedBigUint {
    let mut bytes = Zeroizing::new(vec![0; x.encoded_length()]);
    x.encode_to(&mut bytes);
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    value
}
