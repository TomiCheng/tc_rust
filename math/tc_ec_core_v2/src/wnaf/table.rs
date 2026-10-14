use alloc::vec::Vec;
use crate::Point;

use super::MAX_COMPACT_WIDTH;

/// 呼叫端持有的 wNAF 奇數倍點預算表。
#[derive(Clone, Debug)]
pub struct WNafTable<P> {
    width: usize,
    precomputed: Vec<P>,
    precomputed_negated: Option<Vec<P>>,
}

impl<P: Point> WNafTable<P> {
    /// 建立 `P, 3P, 5P, ...`，並可選擇一併保存其負值。
    pub fn new(point: &P, width: usize, include_negated: bool) -> Self {
        assert!(
            (2..=MAX_COMPACT_WIDTH).contains(&width),
            "wNAF table width must be in the range 2..=16"
        );
        let count = 1_usize << (width - 2);
        let twice = point.double();
        let mut precomputed = Vec::with_capacity(count);
        let mut current = point.clone();
        precomputed.push(current.clone());
        for _ in 1..count {
            current = current.add(&twice);
            precomputed.push(current.clone());
        }
        crate::algo::normalize_all(&mut precomputed).expect("precomputed points share a valid curve");
        let precomputed_negated =
            include_negated.then(|| precomputed.iter().map(Point::negate).collect::<Vec<_>>());
        Self {
            width,
            precomputed,
            precomputed_negated,
        }
    }

    /// 預算表的窗寬。
    pub const fn width(&self) -> usize {
        self.width
    }

    /// 正奇數倍點 `P, 3P, 5P, ...`。
    pub fn precomputed(&self) -> &[P] {
        &self.precomputed
    }

    /// 預先保存的負奇數倍點；未要求時為 `None`。
    pub fn precomputed_negated(&self) -> Option<&[P]> {
        self.precomputed_negated.as_deref()
    }

    pub(crate) fn select(&self, digit: i32) -> P {
        let index = digit.unsigned_abs() as usize >> 1;
        if digit < 0 {
            self.precomputed_negated.as_ref().map_or_else(
                || self.precomputed[index].negate(),
                |points| points[index].clone(),
            )
        } else {
            self.precomputed[index].clone()
        }
    }
}