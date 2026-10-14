use tc_asn1::NamedOid;

use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};

fn check_params(params: &KeyGenParams) -> Result<KeyGenParams, SecurityError> {
    match params {
        KeyGenParams::Basic { strength: 1..=1024 }
        | KeyGenParams::Rc2 {
            strength: 1..=1024,
            effective_key_bits: 1..=1024,
        } => Ok(*params),
        _ => Err(SecurityError::InvalidKeyGenParams),
    }
}

pub(super) const RC2: GeneratorEntry = GeneratorEntry::new(
    &["RC2"],
    &[
        NamedOid::new(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02],
            "1.2.840.113549.3.2",
            "rc2CBC",
        ),
        NamedOid::new(
            &[
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x07,
            ],
            "1.2.840.113549.1.9.16.3.7",
            "id-alg-CMSRC2wrap",
        ),
    ],
    KeyGenParams::Basic { strength: 128 },
    check_params,
);
