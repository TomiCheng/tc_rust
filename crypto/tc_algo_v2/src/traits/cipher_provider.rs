use tc_asn1::Asn1Oid;

use super::{Cipher, CipherDirection, CipherEntry, Params};
use crate::{AlgoError, ErrorKind};

pub trait CipherProvider {
    // No two of the entries have the same name
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn CipherEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Cipher>>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Cipher>>;

    fn encrypt_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        run(
            self.get_by_name(name),
            CipherDirection::Encrypt,
            params,
            input,
        )
    }

    fn encrypt_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        run(
            self.get_by_oid(oid),
            CipherDirection::Encrypt,
            params,
            input,
        )
    }

    fn decrypt_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        run(
            self.get_by_name(name),
            CipherDirection::Decrypt,
            params,
            input,
        )
    }

    fn decrypt_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        run(
            self.get_by_oid(oid),
            CipherDirection::Decrypt,
            params,
            input,
        )
    }
}

fn run(
    cipher: Option<Box<dyn Cipher>>,
    direction: CipherDirection,
    params: &dyn Params,
    input: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    let mut cipher = cipher.ok_or(AlgoError::new(ErrorKind::UnknownCipher))?;
    cipher.init(direction, params)?;
    let mut output = cipher.update(input)?;
    output.extend(cipher.finalize()?);
    Ok(output)
}
