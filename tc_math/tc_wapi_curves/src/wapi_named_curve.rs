use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_fp_curve::{FpCtCurve, FpCtPoint, FpField, FpVarCurve, FpVarPoint};

/// 質數體上一條具名曲線的網域參數，如 BC 的 `X9ECParameters`：質數 p、係數 a 與 b、階 n、
/// 餘因子 h 與基點 G，皆為大端序的 `N` 位元組。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WapiNamedCurve<const N: usize> {
    pub(crate) p: [u8; N],
    pub(crate) a: [u8; N],
    pub(crate) b: [u8; N],
    pub(crate) order: [u8; N],
    pub(crate) cofactor: u32,
    pub(crate) gx: [u8; N],
    pub(crate) gy: [u8; N],
}

impl<const N: usize> WapiNamedCurve<N> {
    /// 曲線的質數體，每次呼叫重建；曲線借用它，由呼叫端保存。變動時間：參數是公開值。
    pub fn field(&self) -> FpField {
        FpField::new(int(&self.p)).expect("a named curve has an odd prime")
    }

    /// `field` 上的 Ct 曲線，帶階與餘因子；`field` 來自 [`field`](Self::field)。常數時間。
    pub fn ct_curve<'a>(&self, field: &'a FpField) -> FpCtCurve<'a> {
        FpCtCurve::new(
            field,
            &int(&self.a),
            &int(&self.b),
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients lie below p")
    }

    /// `field` 上的 Var 曲線，帶階與餘因子，只用於公開值。變動時間。
    pub fn var_curve<'a>(&self, field: &'a FpField) -> FpVarCurve<'a> {
        FpVarCurve::new(
            field,
            &int(&self.a),
            &int(&self.b),
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients lie below p")
    }

    /// Ct 曲線上的基點 G；`curve` 來自 [`ct_curve`](Self::ct_curve)。常數時間。
    pub fn ct_generator<'a>(&self, curve: &'a FpCtCurve<'a>) -> FpCtPoint<'a> {
        curve
            .create_point(&int(&self.gx), &int(&self.gy))
            .expect("a named generator lies below p")
    }

    /// Var 曲線上的基點 G；建立本身是常數時間，點的運算則依 Var 曲線。
    pub fn var_generator<'a>(&self, curve: &'a FpVarCurve<'a>) -> FpVarPoint<'a> {
        curve
            .create_point(&int(&self.gx), &int(&self.gy))
            .expect("a named generator lies below p")
    }
}

fn int(bytes: &[u8]) -> PaddedBigUint {
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(bytes).expect("a named-curve constant decodes")
}
