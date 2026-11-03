use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_f2m_curve::{F2mCtCurve, F2mCtPoint, F2mField, F2mVarCurve, F2mVarPoint};

/// GF(2^m) 上一條具名曲線的網域參數，如 BC 的 `X9ECParameters`：次數 m 與約化多項式、
/// 係數 a 與 b、階 n、餘因子 h 與基點 G，位元組皆為大端序的 `N` 位元組。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X962F2mNamedCurve<const N: usize> {
    pub(crate) m: u32,
    pub(crate) taps: Taps,
    pub(crate) a: [u8; N],
    pub(crate) b: [u8; N],
    pub(crate) order: [u8; N],
    pub(crate) cofactor: u32,
    pub(crate) gx: [u8; N],
    pub(crate) gy: [u8; N],
}

/// 約化多項式在 x^m 與 1 之間的次方，照 BC 的順序。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Taps {
    Trinomial(u32),
    Pentanomial(u32, u32, u32),
}

impl<const N: usize> X962F2mNamedCurve<N> {
    /// 曲線的二元體，每次呼叫重建。變動時間：參數是公開值。
    pub fn field(&self) -> F2mField {
        match self.taps {
            Taps::Trinomial(k) => F2mField::trinomial(self.m, k),
            Taps::Pentanomial(k1, k2, k3) => F2mField::pentanomial(self.m, k1, k2, k3),
        }
        .expect("a named curve has a valid reduction polynomial")
    }

    /// Ct 曲線，帶自己的體、階與餘因子。變動時間：參數是公開值。
    pub fn ct_curve(&self) -> F2mCtCurve {
        F2mCtCurve::new(
            self.field(),
            &self.a,
            &self.b,
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients are reduced")
    }

    /// Var 曲線，帶自己的體、階與餘因子，只用於公開值。變動時間。
    pub fn var_curve(&self) -> F2mVarCurve {
        F2mVarCurve::new(
            self.field(),
            &self.a,
            &self.b,
            Some(int(&self.order)),
            Some(PaddedBigUint::from(self.cofactor)),
        )
        .expect("named-curve coefficients are reduced")
    }

    /// Ct 曲線上的基點 G；`curve` 來自 [`ct_curve`](Self::ct_curve)。常數時間。
    pub fn ct_generator<'a>(&self, curve: &'a F2mCtCurve) -> F2mCtPoint<'a> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator is reduced")
    }

    /// Var 曲線上的基點 G，只用於公開的點。變動時間。
    pub fn var_generator<'a>(&self, curve: &'a F2mVarCurve) -> F2mVarPoint<'a> {
        curve
            .create_point(&self.gx, &self.gy)
            .expect("a named generator is reduced")
    }
}

fn int(bytes: &[u8]) -> PaddedBigUint {
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(bytes).expect("a named-curve constant decodes")
}
