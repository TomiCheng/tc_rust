use rand_core::CryptoRng;
use tc_asn1::NamedOid;

use super::random_key;
use crate::generate::KeyGenParams;
use crate::generate::key::KeyGeneratorEntry;
use crate::params::SecretKey;
use crate::{AlgoError, ErrorKind};

// The NIST AES OIDs sit under 2.16.840.1.101.3.4.1 and differ only in the last arc
macro_rules! nist_aes {
    ($arc:literal, $dotted:literal, $name:literal) => {
        NamedOid::new(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, $arc],
            $dotted,
            $name,
        )
    };
}

// Any of the three AES sizes, whichever row is asked; as tc_security, a size AES does not have
// is refused in init
fn check_params(params: &KeyGenParams) -> Result<(), AlgoError> {
    match params {
        KeyGenParams::Strength {
            bits: 128 | 192 | 256,
        } => Ok(()),
        _ => Err(AlgoError::new(ErrorKind::InvalidKeyGenParams)),
    }
}

fn generate(params: &KeyGenParams, rng: &mut dyn CryptoRng) -> Result<SecretKey, AlgoError> {
    match params {
        KeyGenParams::Strength { bits } => Ok(random_key(*bits, rng)),
        #[allow(unreachable_patterns, reason = "every other variant may be off")]
        _ => Err(AlgoError::new(ErrorKind::InvalidKeyGenParams)),
    }
}

// Without a size it makes 192 bits, as Bouncy Castle does; Bouncy Castle's AESWRAP comes here too
pub(super) const AES: KeyGeneratorEntry = KeyGeneratorEntry::new(
    &["AES", "AESWRAP"],
    &[],
    Some(KeyGenParams::Strength { bits: 192 }),
    check_params,
    generate,
);

// The OIDs follow Bouncy Castle: every mode and key wrap of this size comes to this row
pub(super) const AES128: KeyGeneratorEntry = KeyGeneratorEntry::new(
    &["AES128"],
    &[
        nist_aes!(0x01, "2.16.840.1.101.3.4.1.1", "id-aes128-ECB"),
        nist_aes!(0x02, "2.16.840.1.101.3.4.1.2", "id-aes128-CBC"),
        nist_aes!(0x03, "2.16.840.1.101.3.4.1.3", "id-aes128-OFB"),
        nist_aes!(0x04, "2.16.840.1.101.3.4.1.4", "id-aes128-CFB"),
        nist_aes!(0x05, "2.16.840.1.101.3.4.1.5", "id-aes128-wrap"),
        nist_aes!(0x06, "2.16.840.1.101.3.4.1.6", "id-aes128-GCM"),
        nist_aes!(0x07, "2.16.840.1.101.3.4.1.7", "id-aes128-CCM"),
        nist_aes!(0x08, "2.16.840.1.101.3.4.1.8", "id-aes128-wrap-pad"),
    ],
    Some(KeyGenParams::Strength { bits: 128 }),
    check_params,
    generate,
);

pub(super) const AES192: KeyGeneratorEntry = KeyGeneratorEntry::new(
    &["AES192"],
    &[
        nist_aes!(0x15, "2.16.840.1.101.3.4.1.21", "id-aes192-ECB"),
        nist_aes!(0x16, "2.16.840.1.101.3.4.1.22", "id-aes192-CBC"),
        nist_aes!(0x17, "2.16.840.1.101.3.4.1.23", "id-aes192-OFB"),
        nist_aes!(0x18, "2.16.840.1.101.3.4.1.24", "id-aes192-CFB"),
        nist_aes!(0x19, "2.16.840.1.101.3.4.1.25", "id-aes192-wrap"),
        nist_aes!(0x1a, "2.16.840.1.101.3.4.1.26", "id-aes192-GCM"),
        nist_aes!(0x1b, "2.16.840.1.101.3.4.1.27", "id-aes192-CCM"),
        nist_aes!(0x1c, "2.16.840.1.101.3.4.1.28", "id-aes192-wrap-pad"),
    ],
    Some(KeyGenParams::Strength { bits: 192 }),
    check_params,
    generate,
);

pub(super) const AES256: KeyGeneratorEntry = KeyGeneratorEntry::new(
    &["AES256"],
    &[
        nist_aes!(0x29, "2.16.840.1.101.3.4.1.41", "id-aes256-ECB"),
        nist_aes!(0x2a, "2.16.840.1.101.3.4.1.42", "id-aes256-CBC"),
        nist_aes!(0x2b, "2.16.840.1.101.3.4.1.43", "id-aes256-OFB"),
        nist_aes!(0x2c, "2.16.840.1.101.3.4.1.44", "id-aes256-CFB"),
        nist_aes!(0x2d, "2.16.840.1.101.3.4.1.45", "id-aes256-wrap"),
        nist_aes!(0x2e, "2.16.840.1.101.3.4.1.46", "id-aes256-GCM"),
        nist_aes!(0x2f, "2.16.840.1.101.3.4.1.47", "id-aes256-CCM"),
        nist_aes!(0x30, "2.16.840.1.101.3.4.1.48", "id-aes256-wrap-pad"),
    ],
    Some(KeyGenParams::Strength { bits: 256 }),
    check_params,
    generate,
);
