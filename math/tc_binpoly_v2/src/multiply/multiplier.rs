/// The multiplication backend, picked once at construction as BC's `CreateBinPolyMul` does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Multiplier {
    ScalarMedium,
    ScalarLarge,
}
