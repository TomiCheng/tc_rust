use alloc::format;
use alloc::string::String;

use tc_constant_time::fixed_time_eq;
use tc_zeroize::Zeroize;

use super::eks_blowfish::derive;
use super::generator::check_cost;
use super::{Bcrypt, BcryptError, BcryptVersion, base64};

/// bcrypt as OpenBSD's 60-character hash strings, BC's `OpenBsdBCrypt`:
/// `$2y$10$` followed by the salt in 22 characters and the hash in 31.
///
/// The password is terminated with 0x00 and cut at 72 bytes, so bytes past the 72nd are
/// ignored, as in every bcrypt.
pub struct OpenBsdBcrypt;

impl OpenBsdBcrypt {
    /// The hash string of `password` under `salt` with `2^cost` rounds, labelled `$2y$`.
    ///
    /// As [`generate_with_version`](Self::generate_with_version).
    pub fn generate(password: &[u8], salt: &[u8; 16], cost: u8) -> Result<String, BcryptError> {
        Self::generate_with_version(BcryptVersion::default(), password, salt, cost)
    }

    /// The hash string of `password` under `salt` with `2^cost` rounds, labelled `version`.
    ///
    /// Fails when the cost is outside 4..=31.
    ///
    /// **Variable time (cache timing):** as [`Bcrypt::generate`], which this runs. The
    /// encoding looks its characters up in a 64-byte table, one cache line. The password copy
    /// and the raw hash are wiped before returning.
    pub fn generate_with_version(
        version: BcryptVersion,
        password: &[u8],
        salt: &[u8; 16],
        cost: u8,
    ) -> Result<String, BcryptError> {
        check_cost(cost)?;

        let mut key = [0; Bcrypt::MAX_PASSWORD_BYTES];
        let copied = password.len().min(Bcrypt::MAX_PASSWORD_BYTES);
        key[..copied].copy_from_slice(&password[..copied]);
        let len = (password.len() + 1).min(Bcrypt::MAX_PASSWORD_BYTES);
        let mut hash = derive(&key[..len], salt, cost);
        key.zeroize();

        let mut out = format!("${}${cost:02}$", version.as_str());
        base64::encode(salt, &mut out);
        // 最後一個位元組不進字串，照 OpenBSD
        base64::encode(&hash[..23], &mut out);
        hash.zeroize();
        Ok(out)
    }

    /// Whether `password` matches `hash`, a string from [`generate`](Self::generate) or
    /// another bcrypt with version `2a`, `2b` or `2y`.
    ///
    /// Fails when the string is malformed, its version unsupported or its cost outside
    /// 4..=31; a well-formed string with the wrong hash gives `Ok(false)`.
    ///
    /// **Variable time (cache timing):** as [`Bcrypt::generate`], which this runs. Reading the
    /// string branches only on the string, and the hashes are compared in constant time, unlike
    /// BC's string comparison.
    pub fn check_password(hash: &str, password: &[u8]) -> Result<bool, BcryptError> {
        let text = hash.as_bytes();
        if text.len() != 60 || text[0] != b'$' || text[3] != b'$' || text[6] != b'$' {
            return Err(BcryptError::MalformedHash);
        }
        let version =
            BcryptVersion::from_label(&text[1..3]).ok_or(BcryptError::UnsupportedVersion)?;
        let cost = match text[4..6] {
            [tens @ b'0'..=b'9', units @ b'0'..=b'9'] => (tens - b'0') * 10 + (units - b'0'),
            _ => return Err(BcryptError::MalformedHash),
        };
        let salt = base64::decode_salt(&text[7..29]).ok_or(BcryptError::MalformedHash)?;

        let expected = Self::generate_with_version(version, password, &salt, cost)?;
        Ok(fixed_time_eq(expected.as_bytes(), text))
    }
}
