/// The version a hash string starts with. All three compute the same hash here; they differ
/// only in which bugs of other implementations the label rules out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum BcryptVersion {
    /// `$2a$`, the original; some older implementations hashed 8-bit passwords wrongly under it.
    V2a,
    /// `$2b$`, OpenBSD's after its fix for passwords over 255 bytes.
    V2b,
    /// `$2y$`, crypt_blowfish's after its fix for 8-bit passwords; BC's default.
    #[default]
    V2y,
}

impl BcryptVersion {
    /// The two characters between the first two `$`. Constant time.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2a => "2a",
            Self::V2b => "2b",
            Self::V2y => "2y",
        }
    }

    pub(super) fn from_label(label: &[u8]) -> Option<Self> {
        match label {
            b"2a" => Some(Self::V2a),
            b"2b" => Some(Self::V2b),
            b"2y" => Some(Self::V2y),
            _ => None,
        }
    }
}
