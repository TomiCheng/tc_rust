use super::Curve;

/// 標記曲線的所有運算都是常數時間，秘密的點與純量可以交給它。
///
/// 沒有方法；由實作者保證，包括 [`Curve::multiply`]。
pub trait ConstantTime: Curve {}
