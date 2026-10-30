use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_f2m_curve::F2mCtCurve;
use tc_fp_curve::FpCtCurve;
use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve};

/// SM2 能用的曲線：常數時間的曲線，並能解出 SEC 1 編碼的點，以讀取密文的 C1。
///
/// 只實作在常數時間的曲線上，因為 SM2 會以秘密的 k 與 d 乘點。各曲線的 `decode_point`
/// 是自己的方法，`tc_ec_core` 沒有共用的 trait，所以在這裡補上。
pub trait Sm2Curve: Curve<Scalar = PaddedBigUint> {
    /// 解出 SEC 1 編碼的點並檢查在曲線上，不檢查子群，同 BC 的 `DecodePoint`。變動時間：
    /// 只用於公開的編碼。
    fn decode_point(&self, encoded: &[u8]) -> Option<Self::Point>;
}

impl<'a> Sm2Curve for &'a FpCtCurve<'a> {
    /// 交給 [`FpCtCurve::decode_point`]。變動時間：只用於公開的編碼。
    fn decode_point(&self, encoded: &[u8]) -> Option<Self::Point> {
        FpCtCurve::decode_point(self, encoded).ok()
    }
}

impl Sm2Curve for &SecPCtCurve<SM2P256V1FieldElement> {
    /// 交給 [`SecPCtCurve::decode_point`]。變動時間：只用於公開的編碼。
    fn decode_point(&self, encoded: &[u8]) -> Option<Self::Point> {
        SecPCtCurve::decode_point(self, encoded).ok()
    }
}

impl Sm2Curve for &F2mCtCurve {
    /// 交給 [`F2mCtCurve::decode_point`]。變動時間：只用於公開的編碼。
    fn decode_point(&self, encoded: &[u8]) -> Option<Self::Point> {
        F2mCtCurve::decode_point(self, encoded).ok()
    }
}
