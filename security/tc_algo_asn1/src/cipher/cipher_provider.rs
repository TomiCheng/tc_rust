use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::cipher::Asn1Cipher;

pub trait CipherProvider: Send + Sync {
    // A cipher to encrypt with by its name or an alias, the case of which does not matter, with
    // fresh parameters such as a random IV; UnknownCipher when no row has the name
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Asn1Cipher>, AlgoAsn1Error>;

    // The cipher an AlgorithmIdentifier being read calls for, with its parameters, to decrypt;
    // UnknownCipher when no row matches it. Encrypting with it reuses those parameters, which a
    // nonce must never be
    fn get_by_id(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Cipher>, AlgoAsn1Error>;
}
