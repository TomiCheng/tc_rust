use core::any::Any;

use crate::Params;

// What a DSA key pair is generated to when there is no domain yet: new domain parameters of FIPS
// 186-3, p of `l` bits and q of `n`, generated over SHA-256 at init. A domain already in hand goes
// to the DSA row as a DsaParameters instead. Nothing is checked here: tc_dsa_key judges (l, n), which
// must be (1024, 160), (2048, 224), (2048, 256) or (3072, 256)
#[derive(Clone, Copy, Debug)]
pub struct DsaKeyGenParams {
    l: u32,
    n: u32,
    certainty: u32,
}

impl DsaKeyGenParams {
    // Primes tested to the certainty 80, Bouncy Castle's default for DSA
    pub fn new(l: u32, n: u32) -> Self {
        Self {
            l,
            n,
            certainty: 80,
        }
    }

    pub fn with_certainty(mut self, certainty: u32) -> Self {
        self.certainty = certainty;
        self
    }

    pub fn l(&self) -> u32 {
        self.l
    }

    pub fn n(&self) -> u32 {
        self.n
    }

    pub fn certainty(&self) -> u32 {
        self.certainty
    }
}

impl Params for DsaKeyGenParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
