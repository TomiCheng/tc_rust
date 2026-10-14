use tc_asn1::NamedOid;

use crate::SecurityError;
use crate::generate::{GeneratorEntry, KeyGenParams};

// 同 tc_rsa 與 BC 的預設
const PUBLIC_EXPONENT: u32 = 65537;
const STRENGTH: u32 = 2048;
const CERTAINTY: u32 = 100;

// 只給長度時，公開指數與 certainty 用預設值，同 BC 的 RsaKeyPairGenerator 收到 KeyGenerationParameters；
// 長度與指數合不合用由 tc_rsa 在產生時判定
fn check_params(params: &KeyGenParams) -> Result<KeyGenParams, SecurityError> {
    match *params {
        KeyGenParams::Basic { strength } => Ok(KeyGenParams::Rsa {
            public_exponent: PUBLIC_EXPONENT,
            strength: u32::try_from(strength).map_err(|_| SecurityError::InvalidKeyGenParams)?,
            certainty: CERTAINTY,
        }),
        KeyGenParams::Rsa { .. } => Ok(*params),
    }
}

/// RSA 金鑰對：沒呼叫 init 時產生 2048 bits 的模數，公開指數 65537，同 tc_rsa 與 BC 的預設。
/// OID 照 BC 只有 rsaEncryption。
pub(super) const RSA: GeneratorEntry = GeneratorEntry::new(
    &["RSA"],
    &[NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        "1.2.840.113549.1.1.1",
        "rsaEncryption",
    )],
    KeyGenParams::Rsa {
        public_exponent: PUBLIC_EXPONENT,
        strength: STRENGTH,
        certainty: CERTAINTY,
    },
    check_params,
);
