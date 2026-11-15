use tc_grain128_aead::Grain128AeadEngine;

use super::aead_engine::{AeadEngine, row};
use crate::DefaultAlgoContext;
use crate::cipher::CipherEntry;

// Grain-128AEAD, a finalist of NIST's lightweight cryptography: a key of 16 bytes, a nonce of 12
// and a tag of 8. Bouncy Castle's CipherUtilities has no Grain, so the name is the designers'
pub(super) fn grain128_aead(_: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![row("GRAIN-128AEAD", &[], || {
        Box::new(AeadEngine(Grain128AeadEngine::new()))
    })]
}

#[cfg(test)]
mod tests {
    // The first known answer of tc_grain128_aead's tests
    #[test]
    fn grain128_aead_gives_its_first_known_answer() {
        super::super::aead_engine::assert_empty_vector(
            "GRAIN-128AEAD",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b",
            "d51fd5d16177b434",
        );
    }
}
