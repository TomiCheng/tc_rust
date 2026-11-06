#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BodyLength {
    Fixed(u32),
    Partial(u32),
    Indeterminate,
}
