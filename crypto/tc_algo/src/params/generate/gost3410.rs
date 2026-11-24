use core::any::Any;

use crate::Params;

// What a GOST R 34.10-94 key pair is generated to when there is no domain yet: new domain
// parameters of the standard's annex A, p of `size` bits, generated at init by procedure 2, Bouncy
// Castle's default. A domain already in hand goes to the GOST3410 row as a Gost3410Parameters
// instead. Nothing is checked here: tc_gost3410 judges the size, which must be 512 or 1024
#[derive(Clone, Copy, Debug)]
pub struct Gost3410KeyGenParams {
    size: u32,
}

impl Gost3410KeyGenParams {
    pub fn new(size: u32) -> Self {
        Self { size }
    }

    pub fn size(&self) -> u32 {
        self.size
    }
}

impl Params for Gost3410KeyGenParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
