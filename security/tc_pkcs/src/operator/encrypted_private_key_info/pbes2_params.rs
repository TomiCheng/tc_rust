use std::any::Any;

use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_zeroize::Zeroizing;

// The params of PBES2, of RFC 8018: the password, the salt, iteration count and PRF of PBKDF2, and
// the cipher with its IV, as Bouncy Castle's GenerateAlgorithmParameters takes them. The PRF is an
// OID of hmacWithSHA1 and the like, and the cipher one of AES-CBC, AES-CFB, DES-CBC, DES-EDE3-CBC
// or RC2-CBC. The IV is the caller's, one block of random bytes
pub struct Pbes2Params {
    password: Zeroizing<Vec<u8>>,
    salt: Vec<u8>,
    iterations: usize,
    prf: Asn1Oid,
    cipher: Asn1Oid,
    iv: Vec<u8>,
}

impl Pbes2Params {
    pub fn new(
        password: &str,
        salt: Vec<u8>,
        iterations: usize,
        prf: Asn1Oid,
        cipher: Asn1Oid,
        iv: Vec<u8>,
    ) -> Self {
        Self {
            password: Zeroizing::new(password.as_bytes().to_vec()),
            salt,
            iterations,
            prf,
            cipher,
            iv,
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

    pub fn prf(&self) -> &Asn1Oid {
        &self.prf
    }

    pub fn cipher(&self) -> &Asn1Oid {
        &self.cipher
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl Params for Pbes2Params {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
