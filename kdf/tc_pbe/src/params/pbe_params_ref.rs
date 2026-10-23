use crate::PbeParams;

/// Borrowed [`PbeParams`]. The caller owns the bytes and wipes them; nothing is checked here,
/// each generator checks its parameters in `init`. There is no `Debug`, so the password is not
/// printed.
#[derive(Clone, Copy)]
pub struct PbeParamsRef<'a> {
    password: &'a [u8],
    salt: &'a [u8],
    iteration_count: usize,
}

impl<'a> PbeParamsRef<'a> {
    /// As BC's `Init(password, salt, iterationCount)`. Constant time.
    pub const fn new(password: &'a [u8], salt: &'a [u8], iteration_count: usize) -> Self {
        Self {
            password,
            salt,
            iteration_count,
        }
    }
}

impl PbeParams for PbeParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn password(&self) -> &[u8] {
        self.password
    }

    /// Constant time: returns the slice without reading it.
    fn salt(&self) -> &[u8] {
        self.salt
    }

    /// Constant time.
    fn iteration_count(&self) -> usize {
        self.iteration_count
    }
}
