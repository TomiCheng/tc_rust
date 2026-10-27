/// The Argon2 version, `v` in RFC 9106.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Argon2Version {
    /// 0x10, the original: passes after the first overwrite the blocks instead of XORing into
    /// them.
    V10,
    /// 0x13, RFC 9106's and BC's default.
    #[default]
    V13,
}

impl Argon2Version {
    pub(super) const fn id(self) -> u32 {
        match self {
            Self::V10 => 0x10,
            Self::V13 => 0x13,
        }
    }
}
