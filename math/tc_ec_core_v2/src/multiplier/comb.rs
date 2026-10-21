//! BC 的 `FixedPointCombMultiplier` 與 `FixedPointUtilities`：純量依階的位元數排成 w 列、
//! d 行的梳子，每行的 w 個位元合成索引，查一張 2^w 項的表，所以每行只需一次倍點與一次
//! 加法，總共 d 次，不是逐位元的倍點。表要建一次，約等於一次純量乘法，重複使用才划算。

use super::BaseMultiplier;
use crate::algo::normalize_all;
use crate::{Curve, Point, Scalar};
use alloc::vec;
use alloc::vec::Vec;
use tc_bigint::PaddedBigUint;
use tc_constant_time::{ConditionallySelectable, ConstantTimeEq};

/// BC 的 `FixedPointCombMultiplier`，查表讀遍整張表。純量與結果是常數時間；建表只碰公開的
/// 基點，是變動時間。
///
/// 要求點能常數時間選擇，也就是 Fp 的 Ct 曲線；這個界限只保證查表，群運算本身是否常數時間
/// 取決於點型別，Fp 的 Ct 曲線是完備公式。純量的位元數超過階時 panic，如 BC 擲出例外；
/// 這個檢查只透露純量是否太寬。
pub struct CombCt<C: Curve> {
    table: Table<C::Point>,
}

/// 建表為變動時間，基點須公開。
impl<C> BaseMultiplier<C> for CombCt<C>
where
    C: Curve<Scalar = PaddedBigUint>,
    C::Point: ConditionallySelectable,
{
    fn new(base: C::Point) -> Self {
        Self {
            table: Table::new(base),
        }
    }

    fn multiply(&self, scalar: &PaddedBigUint) -> C::Point {
        let table = &self.table;
        let width = scalar.as_limbs().len() * tc_bigint::Word::BITS as usize;
        let mut high = 0u8;
        for j in table.size..width {
            high |= u8::from(scalar.bit(j as u32));
        }
        assert!(high == 0, "the comb takes scalars no wider than the order");
        table.multiply(
            |j| u32::from(scalar.bit(j as u32)),
            |points, index| {
                let mut selected = points[0].clone();
                for (i, entry) in (0u32..).zip(points).skip(1) {
                    selected = C::Point::conditional_select(&selected, entry, i.ct_eq(&index));
                }
                selected
            },
        )
    }
}

/// BC 的 `FixedPointCombMultiplier`，直接以索引查表。變動時間，只用於公開純量。純量的
/// 位元數超過階時 panic，如 BC 擲出例外。
pub struct CombVar<C: Curve> {
    table: Table<C::Point>,
}

/// 變動時間。
impl<C: Curve> BaseMultiplier<C> for CombVar<C> {
    fn new(base: C::Point) -> Self {
        Self {
            table: Table::new(base),
        }
    }

    fn multiply(&self, scalar: &C::Scalar) -> C::Point {
        let table = &self.table;
        assert!(
            scalar.bit_length() <= table.size,
            "the comb takes scalars no wider than the order"
        );
        table.multiply(
            |j| u32::from(scalar.test_bit(j)),
            |points, index| points[index as usize].clone(),
        )
    }
}

// BC 的 `FixedPointPreCompInfo`：points[i] = P + Σ 2^(bd)·P，b 走過 i 的每個位元；
// offset = P − 2^d·P，抵銷每行都多加的那個 P。表中沒有無窮遠點。
struct Table<P> {
    points: Vec<P>,
    offset: P,
    size: usize,
    width: usize,
    columns: usize,
}

impl<P: Point> Table<P> {
    fn new(base: P) -> Self {
        let size = base
            .curve()
            .order()
            .expect("the comb needs the order")
            .bit_length();
        let width = if size > 250 { 6 } else { 5 };
        let columns = size.div_ceil(width);

        let mut pow2 = Vec::with_capacity(width + 1);
        pow2.push(base.clone());
        for i in 1..width {
            let next = pow2[i - 1].times_pow2(columns);
            pow2.push(next);
        }
        pow2.push(pow2[0].add(&pow2[1].negate()));
        let _ = normalize_all(&mut pow2);

        let n = 1 << width;
        let mut points = vec![base; n];
        for bit in (0..width).rev() {
            let step = 1 << bit;
            for i in (step..n).step_by(step << 1) {
                points[i] = points[i - step].add(&pow2[bit]);
            }
        }
        let _ = normalize_all(&mut points);

        Self {
            points,
            offset: pow2.pop().expect("the offset was pushed last"),
            size,
            width,
            columns,
        }
    }

    // 第 i 行（i 從 1 到 d）的索引由位元 j = (w − 1 − t)·d + (d − i) 組成，t 從 0 到 w − 1，
    // 高位在前；圈數只看階的寬度。
    fn multiply(&self, bit: impl Fn(usize) -> u32, lookup: impl Fn(&[P], u32) -> P) -> P {
        let full = self.width * self.columns;
        let mut result = self.offset.infinity();
        for i in 1..=self.columns {
            let mut index = 0;
            for t in 0..self.width {
                index = (index << 1) | bit(full - i - t * self.columns);
            }
            result = result.twice_plus(&lookup(&self.points, index));
        }
        result.add(&self.offset)
    }
}
