//! 二元擴張體的不可變共用定義。
//!
//! 每個體域只建立一次具體 [`BinPolyMultiplier`] 與 [`ItohTsujii`]；曲線與
//! 所有元素透過 `Arc` 共用，不需要 `Box<dyn ...>` 或執行期 trait object。

use tc_binpoly::{BinPolyError, BinPolyMultiplier, ItohTsujii};

/// 約簡多項式的形狀。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ReductionPolynomial {
    /// `x^m + x^k1 + 1`。
    Trinomial { k1: usize },
    /// `x^m + x^k3 + x^k2 + x^k1 + 1`。
    Pentanomial { k1: usize, k2: usize, k3: usize },
}

/// `GF(2^m) = GF(2)[x] / r(x)` 的共用定義。
#[derive(Clone, Debug)]
pub struct F2mField {
    m: usize,
    reduction: ReductionPolynomial,
    multiplier: BinPolyMultiplier,
    inverter: ItohTsujii,
}

impl F2mField {
    /// 建立以 `x^m + x^k1 + 1` 約簡的體域。
    pub fn trinomial(m: usize, k1: usize) -> Result<Self, BinPolyError> {
        Self::new(
            m,
            ReductionPolynomial::Trinomial { k1 },
            BinPolyMultiplier::trinomial(m, k1)?,
        )
    }

    /// 建立以五項式約簡的體域。
    pub fn pentanomial(m: usize, k1: usize, k2: usize, k3: usize) -> Result<Self, BinPolyError> {
        Self::new(
            m,
            ReductionPolynomial::Pentanomial { k1, k2, k3 },
            BinPolyMultiplier::pentanomial(m, k1, k2, k3)?,
        )
    }

    fn new(
        m: usize,
        reduction: ReductionPolynomial,
        multiplier: BinPolyMultiplier,
    ) -> Result<Self, BinPolyError> {
        let inverter = ItohTsujii::new(multiplier.clone())?;
        Ok(Self {
            m,
            reduction,
            multiplier,
            inverter,
        })
    }

    /// 體域度數 `m`。
    pub const fn m(&self) -> usize {
        self.m
    }

    /// 元素所需的 `u64` limb 數量。
    pub fn size(&self) -> usize {
        self.multiplier.size()
    }

    /// 第一個約簡 tap。
    pub const fn k1(&self) -> usize {
        match self.reduction {
            ReductionPolynomial::Trinomial { k1 } | ReductionPolynomial::Pentanomial { k1, .. } => {
                k1
            }
        }
    }

    /// 第二個約簡 tap；三項式依 BC 慣例回傳零。
    pub const fn k2(&self) -> usize {
        match self.reduction {
            ReductionPolynomial::Pentanomial { k2, .. } => k2,
            ReductionPolynomial::Trinomial { .. } => 0,
        }
    }

    /// 第三個約簡 tap；三項式依 BC 慣例回傳零。
    pub const fn k3(&self) -> usize {
        match self.reduction {
            ReductionPolynomial::Pentanomial { k3, .. } => k3,
            ReductionPolynomial::Trinomial { .. } => 0,
        }
    }

    /// 約簡多項式形狀。
    pub const fn reduction(&self) -> &ReductionPolynomial {
        &self.reduction
    }

    /// 體域的具體乘法器。
    pub const fn multiplier(&self) -> &BinPolyMultiplier {
        &self.multiplier
    }

    /// 與乘法器共用同一模多項式的 Itoh–Tsujii 反元素器。
    pub const fn inverter(&self) -> &ItohTsujii {
        &self.inverter
    }
}

impl PartialEq for F2mField {
    fn eq(&self, other: &Self) -> bool {
        self.m == other.m && self.reduction == other.reduction
    }
}

impl Eq for F2mField {}

impl core::hash::Hash for F2mField {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.m.hash(state);
        self.reduction.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_keep_concrete_operators_and_report_shape() {
        let tri = F2mField::trinomial(233, 74).unwrap();
        assert_eq!((tri.m(), tri.size()), (233, 4));
        assert_eq!((tri.k1(), tri.k2(), tri.k3()), (74, 0, 0));
        assert_eq!(tri.multiplier(), tri.inverter().multiplier());

        let penta = F2mField::pentanomial(163, 3, 6, 7).unwrap();
        assert_eq!((penta.k1(), penta.k2(), penta.k3()), (3, 6, 7));
        assert_ne!(tri, penta);
    }
}
