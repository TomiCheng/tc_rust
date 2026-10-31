use crate::{EcMqvError, MqvPrivateParams, MqvPublicParams};
use alloc::vec;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::EcPrivateKey;
use tc_modular::{ModAdd, ModMul, NonZero};
use tc_zeroize::Zeroizing;

/// BC 的 `ECMqvBasicAgreement`（與 `ECMqvRawAgreement`）：SEC 1 3.4 的 ECMQV 原語，結果是
/// 共享點的 x 座標。以常數時間的曲線上的金鑰初始化，私鑰才不會外洩。
pub struct EcMqvBasicAgreement<C: Curve<Scalar = PaddedBigUint>> {
    state: Option<State<C>>,
}

/// `init` 檢查過的兩把私鑰與自己的臨時公鑰點。
struct State<C: Curve<Scalar = PaddedBigUint>> {
    static_key: EcPrivateKey<C>,
    ephemeral_key: EcPrivateKey<C>,
    ephemeral_point: C::Point,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcMqvBasicAgreement<C> {
    /// 尚未 `init` 的協商。常數時間。
    pub fn new() -> Self {
        Self { state: None }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Default for EcMqvBasicAgreement<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> AgreementInit<MqvPrivateParams<C>>
    for EcMqvBasicAgreement<C>
{
    type Error = EcMqvError;

    /// BC 的 `MqvPrivateParameters` 建構子：兩把私鑰與提供的臨時公鑰要在同一個網域，曲線
    /// 要有階；臨時公鑰省略時以 G 乘臨時私鑰算出。保存私鑰的複本，drop 時清除 d。對私鑰
    /// 是常數時間：曲線是常數時間的。
    fn init(&mut self, params: &MqvPrivateParams<C>) -> Result<(), EcMqvError> {
        self.state = None;
        let g = params.static_key().g();
        if params.ephemeral_key().g() != g {
            return Err(EcMqvError::DomainMismatch);
        }
        g.curve().order().ok_or(EcMqvError::MissingOrder)?;
        let ephemeral_point = match params.ephemeral_public_key() {
            Some(key) if key.g() != g => return Err(EcMqvError::DomainMismatch),
            Some(key) => key.q().clone(),
            None => C::multiply(g, params.ephemeral_key().d()).normalize(),
        };
        self.state = Some(State {
            static_key: params.static_key().clone(),
            ephemeral_key: params.ephemeral_key().clone(),
            ephemeral_point,
        });
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Agreement for EcMqvBasicAgreement<C> {
    type PublicKey = MqvPublicParams<C>;
    type Error = EcMqvError;

    /// BC 的 `GetFieldSize`：一個座標的位元組數。`init` 之前呼叫會 panic。常數時間。
    fn agreement_size(&self) -> usize {
        let state = self.state.as_ref().expect("the agreement is initialized");
        state.static_key.g().curve().one().encoded_length()
    }

    /// 共享點的 x 座標，大端序寫入 `output` 的前段。對私鑰的常數時間程度同曲線的乘點。
    fn calculate_agreement(
        &self,
        public_key: &MqvPublicParams<C>,
        output: &mut [u8],
    ) -> Result<(), EcMqvError> {
        let state = self.state.as_ref().ok_or(EcMqvError::NotInitialized)?;
        let x = agreement_x(state, public_key)?;
        let output = output
            .get_mut(..x.encoded_length())
            .ok_or(EcMqvError::BufferTooSmall)?;
        x.encode_to(output);
        Ok(())
    }
}

/// BC 的 `CalculateMqvAgreement`，SEC 1 3.4：e = ⌈bits(n) / 2⌉，
/// s = d₁ᵤ·Q̄₂ᵤ + d₂ᵤ，P = h·s·(Q₁ᵥ + Q̄₂ᵥ·Q₂ᵥ) mod n，以兩次乘點相加算出；P 為無窮遠點時
/// 回傳錯誤。對私鑰與 P 是常數時間：s、h·s 與係數以模加與模乘算出，乘點用常數時間的
/// 曲線；Q̄ 只依公開的臨時公鑰。
fn agreement_x<C: Curve<Scalar = PaddedBigUint>>(
    state: &State<C>,
    public_key: &MqvPublicParams<C>,
) -> Result<C::Field, EcMqvError> {
    let g = state.static_key.g();
    if public_key.static_key().g() != g || public_key.ephemeral_key().g() != g {
        return Err(EcMqvError::DomainMismatch);
    }
    let curve = g.curve();
    let n = NonZero::new(curve.order().ok_or(EcMqvError::MissingOrder)?.clone())
        .ok_or(EcMqvError::MissingOrder)?;
    let h = curve
        .cofactor()
        .cloned()
        .unwrap_or_else(|| PaddedBigUint::from(1u8));
    let e = n.bits().div_ceil(2);

    let clean = |point: &C::Point| {
        clean_point(curve.clone(), point)
            .ok()
            .filter(|point| !point.is_infinity())
            .ok_or(EcMqvError::InvalidPublicKey)
    };
    let q2u = clean(&state.ephemeral_point)?;
    let q1v = clean(public_key.static_key().q())?;
    let q2v = clean(public_key.ephemeral_key().q())?;

    let q2u_bar = reduce::<C>(&q2u, e);
    let product = Zeroizing::new(state.static_key.d().mod_mul(&q2u_bar, &n));
    let s = Zeroizing::new(product.mod_add(state.ephemeral_key.d(), &n));
    let hs = Zeroizing::new(h.mod_mul(&s, &n));
    let q2v_bar = reduce::<C>(&q2v, e);
    let k1 = Zeroizing::new(q2v_bar.mod_mul(&hs, &n));
    let p = C::multiply(&q1v, &k1)
        .add(&C::multiply(&q2v, &hs))
        .normalize();
    if p.is_infinity() {
        return Err(EcMqvError::InvalidAgreement);
    }
    Ok(p.x().expect("a finite point"))
}

/// Q̄ = 2^e + (x mod 2^e)，x 是點的 x 座標。變動時間：只用於公開的臨時公鑰。
fn reduce<C: Curve>(point: &C::Point, e: u32) -> PaddedBigUint {
    let x = point.x().expect("a finite point");
    let mut bytes = vec![0u8; x.encoded_length()];
    x.encode_to(&mut bytes);
    let Ok(x) = BigUint::from_be(&bytes);
    let mut bound = BigUint::from(0u8);
    bound.set_bit(e, true);
    let mut reduced = x % &bound;
    reduced.set_bit(e, true);
    PaddedBigUint::from(reduced)
}
