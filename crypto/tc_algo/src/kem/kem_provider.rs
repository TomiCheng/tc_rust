use tc_asn1::Asn1Oid;

use crate::kem::{Decapsulator, Encapsulator, KemEntry};
use crate::{AlgoError, Params};

// Bouncy Castle's KemUtilities: an encapsulator for the side that sends, a decapsulator for the one
// that receives, each by name or OID
pub trait KemProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KemEntry> + '_>;

    fn get_encapsulator_by_name(&self, name: &str) -> Result<Box<dyn Encapsulator>, AlgoError>;

    fn get_encapsulator_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Encapsulator>, AlgoError>;

    fn get_decapsulator_by_name(&self, name: &str) -> Result<Box<dyn Decapsulator>, AlgoError>;

    fn get_decapsulator_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Decapsulator>, AlgoError>;

    // Encapsulates to the other side's public key, and gives the encapsulation to send and the
    // secret to keep, the caller's to wipe
    fn encapsulate_by_name(
        &self,
        name: &str,
        public_key: &dyn Params,
    ) -> Result<(Vec<u8>, Vec<u8>), AlgoError> {
        encapsulate(self.get_encapsulator_by_name(name)?, public_key)
    }

    fn encapsulate_by_oid(
        &self,
        oid: &Asn1Oid,
        public_key: &dyn Params,
    ) -> Result<(Vec<u8>, Vec<u8>), AlgoError> {
        encapsulate(self.get_encapsulator_by_oid(oid)?, public_key)
    }

    // Decapsulates with this side's private key, and gives the same secret, the caller's to wipe
    fn decapsulate_by_name(
        &self,
        name: &str,
        private_key: &dyn Params,
        encapsulation: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        decapsulate(
            self.get_decapsulator_by_name(name)?,
            private_key,
            encapsulation,
        )
    }

    fn decapsulate_by_oid(
        &self,
        oid: &Asn1Oid,
        private_key: &dyn Params,
        encapsulation: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        decapsulate(
            self.get_decapsulator_by_oid(oid)?,
            private_key,
            encapsulation,
        )
    }
}

fn encapsulate(
    mut encapsulator: Box<dyn Encapsulator>,
    public_key: &dyn Params,
) -> Result<(Vec<u8>, Vec<u8>), AlgoError> {
    encapsulator.init(public_key)?;
    let mut encapsulation = vec![0; encapsulator.encapsulation_length()];
    let mut secret = vec![0; encapsulator.secret_length()];
    encapsulator.encapsulate(&mut encapsulation, &mut secret)?;
    Ok((encapsulation, secret))
}

fn decapsulate(
    mut decapsulator: Box<dyn Decapsulator>,
    private_key: &dyn Params,
    encapsulation: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    decapsulator.init(private_key)?;
    let mut secret = vec![0; decapsulator.secret_length()];
    decapsulator.decapsulate(encapsulation, &mut secret)?;
    Ok(secret)
}
