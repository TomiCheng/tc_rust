//! The reducer interface — fold a double-width product back to a field element.
//!
//! Mirrors Bouncy Castle `BinPolyMulBase.IReduce`. Concrete reducers live in the
//! per-shape files ([`super::reduce_trinomial`], [`super::reduce_pentanomial`]).

/// Reduces the `2·size`-limb product in `tt` into the `size`-limb `z`, modulo the
/// reducer's field polynomial. The reducer knows its own size.
///
/// `tt` is mutated arbitrarily during reduction (it is scratch) — callers must not
/// read it afterward. Corresponds to bc `IReduce.Reduce`.
pub trait Reduce {
    fn reduce(&self, tt: &mut [u64], z: &mut [u64]);
}
