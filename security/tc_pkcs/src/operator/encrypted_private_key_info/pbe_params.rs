use std::any::Any;

use tc_algo::Params;
use tc_zeroize::Zeroizing;

// The params of a PBE scheme of tc_algo, as PBEwithSHA-1and3-keyDESEDE-CBC: the password, and the
// salt and iteration count its PBEParameter records
pub struct PbeParams {
    password: Zeroizing<Vec<u8>>,
    salt: Vec<u8>,
    iterations: usize,
}

impl PbeParams {
    pub fn new(password: &str, salt: Vec<u8>, iterations: usize) -> Self {
        Self {
            password: Zeroizing::new(password.as_bytes().to_vec()),
            salt,
            iterations,
        }
    }

    pub fn password(&self) -> &str {
        core::str::from_utf8(&self.password).unwrap_or_default()
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn iterations(&self) -> usize {
        self.iterations
    }
}

impl Params for PbeParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
