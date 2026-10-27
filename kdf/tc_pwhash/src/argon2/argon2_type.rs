/// The Argon2 variant, `y` in RFC 9106.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Argon2Type {
    /// Argon2d: reads memory at indices taken from the data, the strongest against GPU
    /// cracking, and leaks through cache timing.
    Argon2d,
    /// Argon2i: reads memory at indices independent of the password, so nothing leaks through
    /// timing, but it is weaker against time-memory tradeoffs.
    Argon2i,
    /// Argon2id: Argon2i for the first half of the first pass and Argon2d after; RFC 9106's
    /// recommendation.
    Argon2id,
}

impl Argon2Type {
    pub(super) const fn id(self) -> u32 {
        match self {
            Self::Argon2d => 0,
            Self::Argon2i => 1,
            Self::Argon2id => 2,
        }
    }
}
