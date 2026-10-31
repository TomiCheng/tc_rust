use crate::EcdhError;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{ModMul, NonZero};
use tc_zeroize::Zeroizing;

/// BC 的 `ECDHCBasicAgreement`（與 `ECDhcRawAgreement`），IEEE P1363 的 ECSVDP-DHC：
/// (h·d)·Q 的 x 座標。餘因子 h 為 1 時與 [`EcdhBasicAgreement`](crate::EcdhBasicAgreement)
/// 相同；否則結果是它的 h 倍點，兩者不相容。以常數時間的曲線上的金鑰初始化，d 才不會
/// 外洩。
pub struct EcdhcBasicAgreement<C: Curve<Scalar = PaddedBigUint>> {
    key: Option<EcPrivateKey<C>>,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcdhcBasicAgreement<C> {
    /// 尚未 `init` 的協商。常數時間。
    pub fn new() -> Self {
        Self { key: None }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Default for EcdhcBasicAgreement<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> AgreementInit<EcPrivateKey<C>> for EcdhcBasicAgreement<C> {
    type Error = EcdhError;

    /// 保存私鑰的複本，drop 時清除 d；同 BC 不做其他檢查。常數時間。
    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), EcdhError> {
        self.key = Some(key.clone());
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Agreement for EcdhcBasicAgreement<C> {
    type PublicKey = EcPublicKey<C>;
    type Error = EcdhError;

    /// BC 的 `GetFieldSize`：一個座標的位元組數。`init` 之前呼叫會 panic。常數時間。
    fn agreement_size(&self) -> usize {
        let key = self.key.as_ref().expect("the agreement is initialized");
        key.g().curve().one().encoded_length()
    }

    /// BC 的 `CalculateAgreementFieldElement`：對方的公鑰要在同一個網域、不是無窮遠點；
    /// P = (h·d mod n)·Q 不得為無窮遠點；x 座標以大端序寫入 `output` 的前段。h·d 以模乘
    /// 算出，對 d 是常數時間；乘點的常數時間程度同曲線。
    fn calculate_agreement(
        &self,
        public_key: &EcPublicKey<C>,
        output: &mut [u8],
    ) -> Result<(), EcdhError> {
        let key = self.key.as_ref().ok_or(EcdhError::NotInitialized)?;
        if key.g() != public_key.g() {
            return Err(EcdhError::WrongDomain);
        }
        let curve = key.g().curve();
        let n = curve.order().expect("a private key's curve has an order");
        let n = NonZero::new(n.clone()).expect("the order is not zero");
        let h = curve
            .cofactor()
            .cloned()
            .unwrap_or_else(|| PaddedBigUint::from(1u8));
        let hd = Zeroizing::new(h.mod_mul(key.d(), &n));

        let q = clean_point(curve.clone(), public_key.q())
            .ok()
            .filter(|q| !q.is_infinity())
            .ok_or(EcdhError::InvalidPublicKey)?;
        let p = C::multiply(&q, &hd);
        if p.is_infinity() {
            return Err(EcdhError::InvalidAgreement);
        }
        let x = p.x().expect("a finite point");
        let output = output
            .get_mut(..x.encoded_length())
            .ok_or(EcdhError::BufferTooSmall)?;
        x.encode_to(output);
        Ok(())
    }
}
