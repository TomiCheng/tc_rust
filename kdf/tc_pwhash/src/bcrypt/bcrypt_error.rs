use core::error::Error;
use core::fmt;

/// A failure to compute a bcrypt hash or to read a hash string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BcryptError {
    /// The raw function got a password longer than 72 bytes; the field holds its length.
    PasswordTooLong(usize),
    /// The cost is outside 4..=31; the field holds it.
    InvalidCost(u8),
    /// The hash string is not 60 characters of `$`, version, `$`, two-digit cost, `$`, and 53
    /// characters of bcrypt's base 64.
    MalformedHash,
    /// The hash string's version is not `2a`, `2b` or `2y`.
    UnsupportedVersion,
}

impl fmt::Display for BcryptError {
    /// Constant time: no field holds secret data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordTooLong(len) => {
                write!(f, "bcrypt password of {len} bytes exceeds 72")
            }
            Self::InvalidCost(cost) => write!(f, "bcrypt cost {cost} is outside 4..=31"),
            Self::MalformedHash => f.write_str("malformed bcrypt hash string"),
            Self::UnsupportedVersion => f.write_str("unsupported bcrypt version"),
        }
    }
}

impl Error for BcryptError {}
