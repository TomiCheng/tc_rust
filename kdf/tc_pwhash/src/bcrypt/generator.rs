use tc_zeroize::Zeroize;

use super::BcryptError;
use super::eks_blowfish::derive;

/// The raw bcrypt function, BC's `BCrypt`: a password, a 16-byte salt and a cost give a
/// 24-byte hash.
///
/// For storing passwords use [`OpenBsdBcrypt`](super::OpenBsdBcrypt), which terminates the
/// password and writes the hash string; this is for test vectors and for interoperating with
/// implementations that keep the 24 bytes.
pub struct Bcrypt;

impl Bcrypt {
    /// The salt length in bytes.
    pub const SALT_BYTES: usize = 16;
    /// The hash length in bytes.
    pub const HASH_BYTES: usize = 24;
    /// The smallest cost: 2^4 rounds.
    pub const MIN_COST: u8 = 4;
    /// The largest cost: 2^31 rounds.
    pub const MAX_COST: u8 = 31;
    /// The longest password in bytes, terminator included, that the key schedule takes.
    pub const MAX_PASSWORD_BYTES: usize = 72;

    /// The bcrypt hash of `password` under `salt` with `2^cost` rounds, BC's
    /// `Generate(password, salt, cost, addTerminator)`.
    ///
    /// `add_terminator` appends the 0x00 byte the specification ends the password with, unless
    /// the password already has 72 bytes; without it, `abc` and `abcabc` hash alike. An empty
    /// password is taken as four zero bytes, as in BC.
    ///
    /// Fails when the password is longer than 72 bytes or the cost is outside 4..=31.
    ///
    /// **Variable time (cache timing):** EksBlowfish looks up its S-boxes at indices derived
    /// from the password, as every bcrypt does, so where a cache is shared the timing can leak
    /// about it. The rest depends only on the cost and the password's length. There is no
    /// constant-time form. The working state and the password copy are wiped before returning.
    pub fn generate(
        password: &[u8],
        salt: &[u8; 16],
        cost: u8,
        add_terminator: bool,
    ) -> Result<[u8; 24], BcryptError> {
        if password.len() > Self::MAX_PASSWORD_BYTES {
            return Err(BcryptError::PasswordTooLong(password.len()));
        }
        check_cost(cost)?;

        let mut key = [0; Self::MAX_PASSWORD_BYTES];
        key[..password.len()].copy_from_slice(password);
        let len = match password.len() {
            0 => 4,
            n if add_terminator && n < Self::MAX_PASSWORD_BYTES => n + 1,
            n => n,
        };
        let hash = derive(&key[..len], salt, cost);
        key.zeroize();
        Ok(hash)
    }
}

pub(super) fn check_cost(cost: u8) -> Result<(), BcryptError> {
    if (Bcrypt::MIN_COST..=Bcrypt::MAX_COST).contains(&cost) {
        Ok(())
    } else {
        Err(BcryptError::InvalidCost(cost))
    }
}
