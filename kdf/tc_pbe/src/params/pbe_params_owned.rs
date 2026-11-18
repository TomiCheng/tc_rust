use alloc::vec::Vec;

use tc_zeroize::Zeroize;

use crate::PbeParams;

/// Owned [`PbeParams`], wiped on drop; nothing is checked here, each generator checks its
/// parameters in `init`. There is no `Debug`, so the password is not printed.
pub struct PbeParamsOwned {
    password: Vec<u8>,
    salt: Vec<u8>,
    iteration_count: usize,
}

impl PbeParamsOwned {
    /// As BC's `Init(password, salt, iterationCount)`, with the password already encoded, as
    /// by [`pkcs5_password_to_utf8_bytes`](crate::pkcs5_password_to_utf8_bytes). Takes the
    /// vectors without copying them. Constant time.
    pub const fn new(password: Vec<u8>, salt: Vec<u8>, iteration_count: usize) -> Self {
        Self {
            password,
            salt,
            iteration_count,
        }
    }
}

impl PbeParams for PbeParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn password(&self) -> &[u8] {
        &self.password
    }

    /// Constant time: returns the slice without reading it.
    fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Constant time.
    fn iteration_count(&self) -> usize {
        self.iteration_count
    }
}

impl Drop for PbeParamsOwned {
    /// Wipes the password and salt. Constant time with respect to them.
    fn drop(&mut self) {
        self.password.zeroize();
        self.salt.zeroize();
    }
}
