use tc_asn1::Asn1Oid;

use crate::cipher::{Cipher, CipherDirection, CipherEntry};
use crate::{AlgoError, Params};

pub trait CipherProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn CipherEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Cipher>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Cipher>, AlgoError>;

    fn encrypt_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        run(
            self.get_by_name(name)?,
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
            self.get_by_oid(oid)?,
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
            self.get_by_name(name)?,
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
            self.get_by_oid(oid)?,
            CipherDirection::Decrypt,
            params,
            input,
        )
    }
}

fn run(
    mut cipher: Box<dyn Cipher>,
    direction: CipherDirection,
    params: &dyn Params,
    input: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    cipher.init(direction, params)?;
    let mut output = cipher.update(input)?;
    output.extend(cipher.finalize()?);
    Ok(output)
}
