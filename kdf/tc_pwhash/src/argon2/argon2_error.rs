use core::error::Error;
use core::fmt;

/// A failure to initialize Argon2 or to hash with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Argon2Error {
    /// The generator has not been initialized.
    NotInitialised,
    /// The number of passes is 0.
    InvalidIterations(u32),
    /// The number of lanes is 0 or `2^24` or more; the field holds it.
    InvalidParallelism(u32),
    /// The memory is 0 KiB, or more blocks than the address space holds; the field holds it.
    InvalidMemory(u32),
    /// The password, salt, secret or associated data is longer than `2^32 - 1` bytes.
    InputTooLong,
    /// The output is shorter than 4 bytes or longer than `2^32 - 1`; the field holds its length.
    InvalidOutputLength(usize),
    /// The memory could not be allocated.
    OutOfMemory,
}

impl fmt::Display for Argon2Error {
    /// Constant time: no field holds secret data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("Argon2 generator not initialised"),
            Self::InvalidIterations(t) => write!(f, "Argon2 pass count {t} is not accepted"),
            Self::InvalidParallelism(p) => write!(f, "Argon2 lane count {p} is not accepted"),
            Self::InvalidMemory(m) => write!(f, "Argon2 memory of {m} KiB is not accepted"),
            Self::InputTooLong => f.write_str("Argon2 input exceeds 2^32 - 1 bytes"),
            Self::InvalidOutputLength(len) => {
                write!(f, "Argon2 output of {len} bytes is outside 4..2^32")
            }
            Self::OutOfMemory => f.write_str("Argon2 memory could not be allocated"),
        }
    }
}

impl Error for Argon2Error {}
