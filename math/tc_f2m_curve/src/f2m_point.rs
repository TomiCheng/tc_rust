//! 二元擴張體曲線點。
//!
//! 座標公式依 Bouncy Castle `F2mPoint` 移植。lambda 座標把 affine
//! `lambda = x + y/x` 放進第二座標；lambda-projective 再以 `Z` 延後反元素，
//! 是二元曲線的預設表示，與 Fp 的 Jacobian 並不是同一套公式。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::BigUint;
use tc_binpoly::{BinaryPoly, BinaryPolyOps};
use tc_ec_core::CoordinateSystem;

use crate::{F2mCurve, F2mFieldElement, F2mInteger, F2mPolynomial};

#[derive(Clone)]
enum Coords<F> {
    Affine { x: F, y: F },
    Homogeneous { x: F, y: F, z: F },
    LambdaAffine { x: F, lambda: F },
    LambdaProjective { x: F, lambda: F, z: F },
}

impl<F> Coords<F> {
    const fn coordinate_system(&self) -> CoordinateSystem {
        match self {
            Self::Affine { .. } => CoordinateSystem::Affine,
            Self::Homogeneous { .. } => CoordinateSystem::Homogeneous,
            Self::LambdaAffine { .. } => CoordinateSystem::LambdaAffine,
            Self::LambdaProjective { .. } => CoordinateSystem::LambdaProjective,
        }
    }

    fn raw_x(&self) -> &F {
        match self {
            Self::Affine { x, .. }
            | Self::Homogeneous { x, .. }
            | Self::LambdaAffine { x, .. }
            | Self::LambdaProjective { x, .. } => x,
        }
    }

    fn raw_y(&self) -> &F {
        match self {
            Self::Affine { y, .. } | Self::Homogeneous { y, .. } => y,
            Self::LambdaAffine { lambda, .. } | Self::LambdaProjective { lambda, .. } => lambda,
        }
    }

    fn z(&self) -> Option<&F> {
        match self {
            Self::Affine { .. } | Self::LambdaAffine { .. } => None,
            Self::Homogeneous { z, .. } | Self::LambdaProjective { z, .. } => Some(z),
        }
    }
}

/// [`F2mCurve`] 上的一個點；`coords == None` 代表無窮遠點。
#[derive(Clone)]
pub struct F2mPoint<P: BinaryPolyOps = BinaryPoly, B: F2mInteger = BigUint> {
    curve: Arc<F2mCurve<P, B>>,
    coords: Option<Coords<F2mFieldElement<P>>>,
}

impl<P: F2mPolynomial, B: F2mInteger> F2mPoint<P, B> {
    /// 以 affine `(x, y)` 建點，再轉成曲線選定的內部座標系。
    pub fn new(curve: Arc<F2mCurve<P, B>>, x: F2mFieldElement<P>, y: F2mFieldElement<P>) -> Self {
        let one = x.one();
        let coords = match curve.coordinate_system() {
            CoordinateSystem::Affine => Coords::Affine { x, y },
            CoordinateSystem::Homogeneous => Coords::Homogeneous { x, y, z: one },
            CoordinateSystem::LambdaAffine => {
                let lambda = if x.is_zero() { y } else { &(&y / &x) + &x };
                Coords::LambdaAffine { x, lambda }
            }
            CoordinateSystem::LambdaProjective => {
                let lambda = if x.is_zero() { y } else { &(&y / &x) + &x };
                Coords::LambdaProjective { x, lambda, z: one }
            }
            _ => unreachable!("F2mCurve rejects unsupported coordinate systems"),
        };
        Self::from_coords(curve, coords)
    }

    fn from_coords(curve: Arc<F2mCurve<P, B>>, coords: Coords<F2mFieldElement<P>>) -> Self {
        debug_assert_eq!(coords.coordinate_system(), curve.coordinate_system());
        Self {
            curve,
            coords: Some(coords),
        }
    }

    /// 建立群單位點。
    pub fn infinity(curve: Arc<F2mCurve<P, B>>) -> Self {
        Self {
            curve,
            coords: None,
        }
    }

    /// 點所屬曲線。
    pub fn curve(&self) -> &Arc<F2mCurve<P, B>> {
        &self.curve
    }

    /// 是否為無窮遠點。
    pub fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// 未正規化的原始 X 座標。
    ///
    /// 投影表示下通常不等於 affine x；呼叫端若要編碼或一般座標，應使用
    /// [`Self::x`] 或先呼叫 [`Self::normalize`]。
    pub fn raw_x(&self) -> Option<&F2mFieldElement<P>> {
        self.coords.as_ref().map(Coords::raw_x)
    }

    /// 未正規化的原始第二座標。
    ///
    /// lambda 座標系中這裡回傳的是 lambda，不是 affine y。
    pub fn raw_y(&self) -> Option<&F2mFieldElement<P>> {
        self.coords.as_ref().map(Coords::raw_y)
    }

    fn projective_z(&self) -> Option<&F2mFieldElement<P>> {
        self.coords.as_ref().and_then(Coords::z)
    }

    /// 正規化後的 affine X 座標。
    pub fn x(&self) -> Option<F2mFieldElement<P>> {
        self.normalize().raw_x().cloned()
    }

    /// 正規化後的 affine Y 座標。
    pub fn y(&self) -> Option<F2mFieldElement<P>> {
        let normalized = self.normalize();
        normalized.affine_y_from_normalized()
    }

    fn affine_y_from_normalized(&self) -> Option<F2mFieldElement<P>> {
        match self.coords.as_ref()? {
            Coords::Affine { y, .. } | Coords::Homogeneous { y, .. } => Some(y.clone()),
            Coords::LambdaAffine { x, lambda } | Coords::LambdaProjective { x, lambda, .. } => {
                if x.is_zero() {
                    Some(lambda.clone())
                } else {
                    Some(&(lambda + x) * x)
                }
            }
        }
    }

    /// 取得指定的投影 Z 分量。
    pub fn get_z_coord(&self, index: usize) -> Option<F2mFieldElement<P>> {
        if index == 0 {
            self.projective_z().cloned()
        } else {
            None
        }
    }

    /// 複製目前座標系的所有 Z 分量。
    pub fn get_z_coords(&self) -> Vec<F2mFieldElement<P>> {
        self.projective_z()
            .map_or_else(Vec::new, |z| alloc::vec![z.clone()])
    }

    /// Affine、lambda-affine、單位點或 `Z == 1` 的點已正規化。
    pub fn is_normalized(&self) -> bool {
        self.coords
            .as_ref()
            .is_none_or(|coords| coords.z().is_none_or(F2mFieldElement::is_one))
    }

    /// 以一次反元素把投影座標縮放到 `Z == 1`。
    pub fn normalize(&self) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        let Some(z) = coords.z() else {
            return self.clone();
        };
        if z.is_one() {
            return self.clone();
        }

        let z_inv = z.invert();
        self.normalize_with_inverse(&z_inv)
    }

    pub(crate) fn normalize_with_inverse(&self, inverse: &F2mFieldElement<P>) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        let Some(z) = coords.z() else {
            return self.clone();
        };
        let z_inv = inverse.clone();
        let one = z.one();
        let normalized = match coords {
            Coords::Homogeneous { x, y, .. } => Coords::Homogeneous {
                x: x * &z_inv,
                y: y * &z_inv,
                z: one,
            },
            Coords::LambdaProjective { x, lambda, .. } => Coords::LambdaProjective {
                x: x * &z_inv,
                lambda: lambda * &z_inv,
                z: one,
            },
            Coords::Affine { .. } | Coords::LambdaAffine { .. } => unreachable!(),
        };
        Self::from_coords(Arc::clone(&self.curve), normalized)
    }

    /// 檢查點是否滿足曲線方程與已知群階。
    pub fn is_valid(&self) -> bool {
        let normalized = self.normalize();
        let (Some(x), Some(y)) = (normalized.raw_x(), normalized.affine_y_from_normalized()) else {
            return true;
        };
        if !self.curve.contains_affine(x, &y) {
            return false;
        }
        self.curve
            .order()
            .is_none_or(|order| self.mul_double_and_add(order).is_infinity())
    }

    /// SEC 1 / X9.62 點編碼。
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let normalized = self.normalize();
        let Some(x) = normalized.raw_x() else {
            return alloc::vec![0x00];
        };
        let y = normalized
            .affine_y_from_normalized()
            .expect("finite point has a y coordinate");
        let length = self.curve.field_element_encoding_length();
        let x_bytes = fixed_be(&x.to_integer::<B>(), length);
        if compressed {
            let tag = if normalized.compression_y_tilde() {
                0x03
            } else {
                0x02
            };
            let mut encoded = Vec::with_capacity(length + 1);
            encoded.push(tag);
            encoded.extend_from_slice(&x_bytes);
            encoded
        } else {
            let mut encoded = Vec::with_capacity(length * 2 + 1);
            encoded.push(0x04);
            encoded.extend_from_slice(&x_bytes);
            encoded.extend_from_slice(&fixed_be(&y.to_integer::<B>(), length));
            encoded
        }
    }

    fn compression_y_tilde(&self) -> bool {
        let Some(coords) = &self.coords else {
            return false;
        };
        let x = coords.raw_x();
        if x.is_zero() {
            return false;
        }
        match coords {
            Coords::LambdaAffine { lambda, .. } | Coords::LambdaProjective { lambda, .. } => {
                lambda.test_bit_zero() != x.test_bit_zero()
            }
            Coords::Affine { y, .. } | Coords::Homogeneous { y, .. } => (y / x).test_bit_zero(),
        }
    }

    /// 點倍乘二。
    pub fn twice(&self) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        if coords.raw_x().is_zero() {
            return Self::infinity(Arc::clone(&self.curve));
        }
        match coords {
            Coords::Affine { x, y } => self.twice_affine(x, y),
            Coords::Homogeneous { x, y, z } => self.twice_homogeneous(x, y, z),
            Coords::LambdaAffine { x, .. } => {
                let y = self
                    .affine_y_from_normalized()
                    .expect("finite point has a y coordinate");
                self.twice_affine(x, &y)
            }
            Coords::LambdaProjective { x, lambda, z } => self.twice_lambda_projective(x, lambda, z),
        }
    }

    fn twice_affine(&self, x: &F2mFieldElement<P>, y: &F2mFieldElement<P>) -> Self {
        let lambda = &(y / x) + x;
        let x3 = &(&lambda.square() + &lambda) + self.curve.a();
        let y3 = x.square_plus_product(&x3, &lambda.add_one());
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    fn twice_homogeneous(
        &self,
        x: &F2mFieldElement<P>,
        y: &F2mFieldElement<P>,
        z: &F2mFieldElement<P>,
    ) -> Self {
        let z_is_one = z.is_one();
        let xz = if z_is_one { x.clone() } else { x * z };
        let yz = if z_is_one { y.clone() } else { y * z };
        let x_sq = x.square();
        let s = &x_sq + &yz;
        let v_sq = xz.square();
        let sv = &s + &xz;
        let h = sv.multiply_plus_product(&s, &v_sq, self.curve.a());
        let x3 = &xz * &h;
        let y3 = x_sq.square().multiply_plus_product(&xz, &h, &sv);
        let z3 = &xz * &v_sq;
        Self::from_coords(
            Arc::clone(&self.curve),
            Coords::Homogeneous {
                x: x3,
                y: y3,
                z: z3,
            },
        )
    }

    fn twice_lambda_projective(
        &self,
        x: &F2mFieldElement<P>,
        lambda: &F2mFieldElement<P>,
        z: &F2mFieldElement<P>,
    ) -> Self {
        let z_is_one = z.is_one();
        let lambda_z = if z_is_one { lambda.clone() } else { lambda * z };
        let z_sq = if z_is_one { z.clone() } else { z.square() };
        let az_sq = if z_is_one {
            self.curve.a().clone()
        } else {
            self.curve.a() * &z_sq
        };
        let t = &(&lambda.square() + &lambda_z) + &az_sq;
        if t.is_zero() {
            return Self::new(Arc::clone(&self.curve), t, self.curve.b().sqrt());
        }

        let x3 = t.square();
        let z3 = if z_is_one { t.clone() } else { &t * &z_sq };
        let lambda3 = if self.curve.b().bit_length() < (self.curve.field_size() >> 1) {
            let t1 = (lambda + x).square();
            let t2 = if self.curve.b().is_one() {
                (&az_sq + &z_sq).square()
            } else {
                az_sq.square_plus_product(self.curve.b(), &z_sq.square())
            };
            let sum = &(&t1 + &t) + &z_sq;
            let mut result = &(&(&sum * &t1) + &t2) + &x3;
            // BC 只在低位元 b 的分支補這項；一般 b 的公式已經把 a 算進去。
            if self.curve.a().is_zero() {
                result = &result + &z3;
            } else if !self.curve.a().is_one() {
                result = &result + &(&self.curve.a().add_one() * &z3);
            }
            result
        } else {
            let xz = if z_is_one { x.clone() } else { x * z };
            &(&xz.square_plus_product(&t, &lambda_z) + &x3) + &z3
        };

        Self::from_coords(
            Arc::clone(&self.curve),
            Coords::LambdaProjective {
                x: x3,
                lambda: lambda3,
                z: z3,
            },
        )
    }

    fn add_affine(
        &self,
        x1: &F2mFieldElement<P>,
        y1: &F2mFieldElement<P>,
        x2: &F2mFieldElement<P>,
        y2: &F2mFieldElement<P>,
    ) -> Self {
        let dx = x1 + x2;
        let dy = y1 + y2;
        if dx.is_zero() {
            return if dy.is_zero() {
                self.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }
        let lambda = &dy / &dx;
        let x3 = &(&(&lambda.square() + &lambda) + &dx) + self.curve.a();
        let y3 = &(&(&lambda * &(x1 + &x3)) + &x3) + y1;
        Self::new(Arc::clone(&self.curve), x3, y3)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_homogeneous(
        &self,
        x1: &F2mFieldElement<P>,
        y1: &F2mFieldElement<P>,
        z1: &F2mFieldElement<P>,
        x2: &F2mFieldElement<P>,
        y2: &F2mFieldElement<P>,
        z2: &F2mFieldElement<P>,
    ) -> Self {
        let z1_is_one = z1.is_one();
        let (u1, v1) = if z1_is_one {
            (y2.clone(), x2.clone())
        } else {
            (y2 * z1, x2 * z1)
        };
        let z2_is_one = z2.is_one();
        let (u2, v2) = if z2_is_one {
            (y1.clone(), x1.clone())
        } else {
            (y1 * z2, x1 * z2)
        };
        let u = &u1 + &u2;
        let v = &v1 + &v2;
        if v.is_zero() {
            return if u.is_zero() {
                self.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }

        let v_sq = v.square();
        let v_cu = &v_sq * &v;
        let w = if z1_is_one {
            z2.clone()
        } else if z2_is_one {
            z1.clone()
        } else {
            z1 * z2
        };
        let uv = &u + &v;
        let a = &uv.multiply_plus_product(&u, &v_sq, self.curve.a()) * &w;
        let a = &a + &v_cu;
        let x3 = &v * &a;
        let v_sq_z2 = if z2_is_one { v_sq } else { &v_sq * z2 };
        let y3 = u
            .multiply_plus_product(x1, &v, y1)
            .multiply_plus_product(&v_sq_z2, &uv, &a);
        let z3 = &v_cu * &w;
        Self::from_coords(
            Arc::clone(&self.curve),
            Coords::Homogeneous {
                x: x3,
                y: y3,
                z: z3,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_lambda_projective(
        &self,
        x1: &F2mFieldElement<P>,
        lambda1: &F2mFieldElement<P>,
        z1: &F2mFieldElement<P>,
        x2: &F2mFieldElement<P>,
        lambda2: &F2mFieldElement<P>,
        z2: &F2mFieldElement<P>,
    ) -> Self {
        if x1.is_zero() {
            if x2.is_zero() {
                return Self::infinity(Arc::clone(&self.curve));
            }
            return self.add_swapped_lambda_point(x2, lambda2, z2);
        }

        let z1_is_one = z1.is_one();
        let (u2, s2) = if z1_is_one {
            (x2.clone(), lambda2.clone())
        } else {
            (x2 * z1, lambda2 * z1)
        };
        let z2_is_one = z2.is_one();
        let (u1, s1) = if z2_is_one {
            (x1.clone(), lambda1.clone())
        } else {
            (x1 * z2, lambda1 * z2)
        };
        let a = &s1 + &s2;
        let mut b = &u1 + &u2;
        if b.is_zero() {
            return if a.is_zero() {
                self.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }

        if x2.is_zero() {
            let normalized = self.normalize();
            let nx = normalized
                .raw_x()
                .expect("finite point has an x coordinate")
                .clone();
            let ny = normalized
                .affine_y_from_normalized()
                .expect("finite point has a y coordinate");
            let slope = &(&ny + lambda2) / &nx;
            let x3 = &(&(&slope.square() + &slope) + &nx) + self.curve.a();
            if x3.is_zero() {
                return Self::new(Arc::clone(&self.curve), x3, self.curve.b().sqrt());
            }
            let y3 = &(&(&slope * &(&nx + &x3)) + &x3) + &ny;
            let lambda3 = &(&y3 / &x3) + &x3;
            return Self::from_coords(
                Arc::clone(&self.curve),
                Coords::LambdaProjective {
                    x: x3,
                    lambda: lambda3,
                    z: nx.one(),
                },
            );
        }

        b = b.square();
        let au1 = &a * &u1;
        let au2 = &a * &u2;
        let x3 = &au1 * &au2;
        if x3.is_zero() {
            return Self::new(Arc::clone(&self.curve), x3, self.curve.b().sqrt());
        }
        let mut abz2 = &a * &b;
        if !z2_is_one {
            abz2 = &abz2 * z2;
        }
        let lambda3 = au2.add(&b).square_plus_product(&abz2, &(lambda1 + z1));
        let mut z3 = abz2;
        if !z1_is_one {
            z3 = &z3 * z1;
        }
        Self::from_coords(
            Arc::clone(&self.curve),
            Coords::LambdaProjective {
                x: x3,
                lambda: lambda3,
                z: z3,
            },
        )
    }

    fn add_swapped_lambda_point(
        &self,
        x: &F2mFieldElement<P>,
        lambda: &F2mFieldElement<P>,
        z: &F2mFieldElement<P>,
    ) -> Self {
        let rhs = Self::from_coords(
            Arc::clone(&self.curve),
            Coords::LambdaProjective {
                x: x.clone(),
                lambda: lambda.clone(),
                z: z.clone(),
            },
        );
        &rhs + self
    }

    /// 計算 `2P + Q`；lambda-projective 使用 BC 的融合公式。
    pub fn twice_plus(&self, rhs: &Self) -> Self {
        if self.is_infinity() {
            return rhs.clone();
        }
        if rhs.is_infinity() {
            return self.twice();
        }
        let Some(Coords::LambdaProjective {
            x: x1,
            lambda: lambda1,
            z: z1,
        }) = &self.coords
        else {
            return &self.twice() + rhs;
        };
        if x1.is_zero() {
            return rhs.clone();
        }
        let Some(Coords::LambdaProjective {
            x: x2,
            lambda: lambda2,
            z: z2,
        }) = &rhs.coords
        else {
            return &self.twice() + rhs;
        };
        if x2.is_zero() || !z2.is_one() {
            return &self.twice() + rhs;
        }

        let x1_sq = x1.square();
        let lambda1_sq = lambda1.square();
        let z1_sq = z1.square();
        let lambda1_z1 = lambda1 * z1;
        let t = &(self.curve.a() * &z1_sq) + &lambda1_sq;
        let t = &t + &lambda1_z1;
        let lambda2_plus_one = lambda2.add_one();
        let a = &(self.curve.a() + &lambda2_plus_one) * &z1_sq;
        let a = &a + &lambda1_sq;
        let a = a.multiply_plus_product(&t, &x1_sq, &z1_sq);
        let x2_z1_sq = x2 * &z1_sq;
        let b = (&x2_z1_sq + &t).square();
        if b.is_zero() {
            return if a.is_zero() {
                rhs.twice()
            } else {
                Self::infinity(Arc::clone(&self.curve))
            };
        }
        if a.is_zero() {
            return Self::new(Arc::clone(&self.curve), a, self.curve.b().sqrt());
        }
        let x3 = &a.square() * &x2_z1_sq;
        let z3 = &(&a * &b) * &z1_sq;
        let lambda3 = (&a + &b)
            .square()
            .multiply_plus_product(&t, &lambda2_plus_one, &z3);
        Self::from_coords(
            Arc::clone(&self.curve),
            Coords::LambdaProjective {
                x: x3,
                lambda: lambda3,
                z: z3,
            },
        )
    }

    /// 計算 `3P`。
    pub fn three_times(&self) -> Self {
        self.twice_plus(self)
    }

    /// 計算 `P * 2^exponent`。
    pub fn times_pow2(&self, exponent: usize) -> Self {
        let mut result = self.clone();
        for _ in 0..exponent {
            result = result.twice();
        }
        result
    }

    /// Koblitz Frobenius `τ(P)`；在 `GF(2^m)` 座標上等於逐分量平方。
    pub fn tau(&self) -> Self {
        self.tau_pow(1)
    }

    /// 一次計算 `τ^count(P)`，讓 WTNAF 可跳過連續零 digit。
    pub fn tau_pow(&self, count: usize) -> Self {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        let coords = match coords {
            Coords::Affine { x, y } => Coords::Affine {
                x: x.square_pow(count),
                y: y.square_pow(count),
            },
            Coords::Homogeneous { x, y, z } => Coords::Homogeneous {
                x: x.square_pow(count),
                y: y.square_pow(count),
                z: z.square_pow(count),
            },
            Coords::LambdaAffine { x, lambda } => Coords::LambdaAffine {
                x: x.square_pow(count),
                lambda: lambda.square_pow(count),
            },
            Coords::LambdaProjective { x, lambda, z } => Coords::LambdaProjective {
                x: x.square_pow(count),
                lambda: lambda.square_pow(count),
                z: z.square_pow(count),
            },
        };
        Self::from_coords(Arc::clone(&self.curve), coords)
    }

    /// 由最高位到最低位執行 double-and-add。
    pub fn mul_double_and_add(&self, scalar: &B) -> Self {
        if self.is_infinity() || scalar.bit_length() == 0 {
            return Self::infinity(Arc::clone(&self.curve));
        }
        let mut result = Self::infinity(Arc::clone(&self.curve));
        let mut bit = scalar.bit_length();
        while bit > 0 {
            bit -= 1;
            result = result.twice();
            if scalar.test_bit(bit) {
                result = &result + self;
            }
        }
        result
    }

    #[allow(clippy::type_complexity)]
    fn equality_parts(
        &self,
    ) -> Option<(
        F2mFieldElement<P>,
        F2mFieldElement<P>,
        Option<F2mFieldElement<P>>,
        usize,
        usize,
    )> {
        let coords = self.coords.as_ref()?;
        match coords {
            Coords::Affine { x, y } => Some((x.clone(), y.clone(), None, 0, 0)),
            Coords::Homogeneous { x, y, z } => Some((x.clone(), y.clone(), Some(z.clone()), 1, 1)),
            Coords::LambdaAffine { x, lambda } => Some((x.clone(), &(lambda + x) * x, None, 0, 0)),
            Coords::LambdaProjective { x, lambda, z } => {
                Some((x.clone(), &(lambda + x) * x, Some(z.clone()), 1, 2))
            }
        }
    }
}

fn fixed_be<B: F2mInteger>(value: &B, length: usize) -> Vec<u8> {
    let mut encoded = alloc::vec![0_u8; length];
    let value_length = value.byte_length_unsigned();
    assert!(value_length <= length, "coordinate exceeds the field width");
    value
        .write_unsigned_be_bytes(&mut encoded[length - value_length..])
        .expect("coordinate output has the exact magnitude width");
    encoded
}

fn scale_power<P: F2mPolynomial>(
    value: &F2mFieldElement<P>,
    z: Option<&F2mFieldElement<P>>,
    power: usize,
) -> F2mFieldElement<P> {
    let Some(z) = z else {
        return value.clone();
    };
    match power {
        0 => value.clone(),
        1 => value * z,
        2 => value * &z.square(),
        _ => unreachable!("F2m equality uses at most Z squared"),
    }
}

impl<P: F2mPolynomial, B: F2mInteger> PartialEq for F2mPoint<P, B> {
    fn eq(&self, other: &Self) -> bool {
        if !(Arc::ptr_eq(&self.curve, &other.curve) || self.curve == other.curve) {
            return false;
        }
        let (Some((x1, y1, z1, xp1, yp1)), Some((x2, y2, z2, xp2, yp2))) =
            (self.equality_parts(), other.equality_parts())
        else {
            return self.is_infinity() && other.is_infinity();
        };
        scale_power(&x1, z2.as_ref(), xp2) == scale_power(&x2, z1.as_ref(), xp1)
            && scale_power(&y1, z2.as_ref(), yp2) == scale_power(&y2, z1.as_ref(), yp1)
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Eq for F2mPoint<P, B> {}

impl<P: BinaryPolyOps, B: F2mInteger> core::fmt::Debug for F2mPoint<P, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.coords {
            None => f.write_str("F2mPoint(infinity)"),
            Some(coords) => f
                .debug_struct("F2mPoint")
                .field("coordinate_system", &coords.coordinate_system())
                .field("x", &coords.raw_x().value().as_limbs())
                .field("raw_y", &coords.raw_y().value().as_limbs())
                .field("z", &coords.z().map(|z| z.value().as_limbs()))
                .finish(),
        }
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Add for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert!(Arc::ptr_eq(&self.curve, &rhs.curve) || self.curve == rhs.curve);
        let Some(left) = &self.coords else {
            return rhs.clone();
        };
        let Some(right) = &rhs.coords else {
            return self.clone();
        };
        match (left, right) {
            (Coords::Affine { x: x1, y: y1 }, Coords::Affine { x: x2, y: y2 }) => {
                self.add_affine(x1, y1, x2, y2)
            }
            (
                Coords::Homogeneous {
                    x: x1,
                    y: y1,
                    z: z1,
                },
                Coords::Homogeneous {
                    x: x2,
                    y: y2,
                    z: z2,
                },
            ) => self.add_homogeneous(x1, y1, z1, x2, y2, z2),
            (Coords::LambdaAffine { x: x1, .. }, Coords::LambdaAffine { x: x2, .. }) => {
                let y1 = self
                    .affine_y_from_normalized()
                    .expect("finite point has a y coordinate");
                let y2 = rhs
                    .affine_y_from_normalized()
                    .expect("finite point has a y coordinate");
                self.add_affine(x1, &y1, x2, &y2)
            }
            (
                Coords::LambdaProjective {
                    x: x1,
                    lambda: lambda1,
                    z: z1,
                },
                Coords::LambdaProjective {
                    x: x2,
                    lambda: lambda2,
                    z: z2,
                },
            ) => self.add_lambda_projective(x1, lambda1, z1, x2, lambda2, z2),
            _ => unreachable!("points on one curve share a coordinate system"),
        }
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Sub for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn sub(self, rhs: Self) -> Self::Output {
        if rhs.is_infinity() {
            self.clone()
        } else {
            self + &(-rhs)
        }
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Neg for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn neg(self) -> Self::Output {
        let Some(coords) = &self.coords else {
            return self.clone();
        };
        if coords.raw_x().is_zero() {
            return self.clone();
        }
        let negated = match coords {
            Coords::Affine { x, y } => Coords::Affine {
                x: x.clone(),
                y: y + x,
            },
            Coords::Homogeneous { x, y, z } => Coords::Homogeneous {
                x: x.clone(),
                y: y + x,
                z: z.clone(),
            },
            Coords::LambdaAffine { x, lambda } => Coords::LambdaAffine {
                x: x.clone(),
                lambda: lambda.add_one(),
            },
            Coords::LambdaProjective { x, lambda, z } => Coords::LambdaProjective {
                x: x.clone(),
                lambda: lambda + z,
                z: z.clone(),
            },
        };
        F2mPoint::from_coords(Arc::clone(&self.curve), negated)
    }
}

impl<P: F2mPolynomial, B: F2mInteger> Mul<&B> for &F2mPoint<P, B> {
    type Output = F2mPoint<P, B>;

    fn mul(self, rhs: &B) -> Self::Output {
        self.mul_double_and_add(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::named_curves::{hex, sect163k1_with};
    use tc_bigint::{BigUint, U256};
    use tc_binpoly::FixedBinaryPoly;

    fn curve_with_coords(
        coordinate_system: CoordinateSystem,
    ) -> (
        Arc<F2mCurve<FixedBinaryPoly<3>, U256>>,
        F2mPoint<FixedBinaryPoly<3>, U256>,
    ) {
        let curve = Arc::new(
            F2mCurve::pentanomial(
                163,
                3,
                6,
                7,
                U256::from(1_u8),
                U256::from(1_u8),
                Some(hex("04000000000000000000020108A2E0CC0D99F8A5EF")),
                Some(U256::from(2_u8)),
            )
            .unwrap()
            .with_coordinate_system(coordinate_system),
        );
        let point = curve.create_point(
            hex("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8"),
            hex("0289070FB05D38FF58321F2E800536D538CCDAA3D9"),
        );
        (curve, point)
    }

    #[test]
    fn every_coordinate_system_matches_affine_group_operations() {
        let scalar = hex::<U256>("051F7A94D308C624B1E975A06D42F89C357E1ABCD");
        let expected = curve_with_coords(CoordinateSystem::Affine)
            .1
            .mul_double_and_add(&scalar)
            .encode(false);
        for coordinate_system in [
            CoordinateSystem::Affine,
            CoordinateSystem::Homogeneous,
            CoordinateSystem::LambdaAffine,
            CoordinateSystem::LambdaProjective,
        ] {
            let (_, point) = curve_with_coords(coordinate_system);
            assert!(point.is_valid(), "{coordinate_system:?}");
            assert_eq!(point.twice(), &point + &point, "{coordinate_system:?}");
            assert_eq!(point.three_times(), &point.twice() + &point);
            assert_eq!(point.twice_plus(&point), point.three_times());
            assert_eq!(
                point.times_pow2(3),
                point.twice().twice().twice(),
                "{coordinate_system:?}"
            );
            assert_eq!(point.mul_double_and_add(&scalar).encode(false), expected);
            assert!((&point + &(-&point)).is_infinity());
        }
    }

    #[test]
    fn projective_equality_uses_cross_products_without_normalizing() {
        for coordinate_system in [
            CoordinateSystem::Homogeneous,
            CoordinateSystem::LambdaProjective,
        ] {
            let (curve, point) = curve_with_coords(coordinate_system);
            let scale = curve.create_field_element(U256::from(7_u8));
            let coords = match point.coords.as_ref().unwrap() {
                Coords::Homogeneous { x, y, z } => Coords::Homogeneous {
                    x: x * &scale,
                    y: y * &scale,
                    z: z * &scale,
                },
                Coords::LambdaProjective { x, lambda, z } => Coords::LambdaProjective {
                    x: x * &scale,
                    lambda: lambda * &scale,
                    z: z * &scale,
                },
                _ => unreachable!(),
            };
            let scaled = F2mPoint::from_coords(curve, coords);
            assert!(!scaled.is_normalized());
            assert_eq!(scaled, point);
            assert_eq!(scaled.normalize().encode(false), point.encode(false));
        }
    }

    #[test]
    fn default_curve_uses_lambda_projective_and_dynamic_backend_still_runs() {
        let (curve, point) = sect163k1_with::<BinaryPoly, BigUint>();
        assert_eq!(
            curve.coordinate_system(),
            CoordinateSystem::LambdaProjective
        );
        assert!(point.is_normalized());
        assert!(point.is_valid());
    }
}
