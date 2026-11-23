use tc_algo::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;

// A signer of tc_algo with the AlgorithmIdentifier it goes by. The key tells the direction, as in
// tc_algo: a private key signs and a public key verifies
pub trait Signer {
    // What a certificate, a CRL or a SignerInfo records for this signature; a TBS takes it before
    // it is signed
    fn algorithm(&self) -> &AlgorithmIdentifier;

    fn init(&mut self, key: &dyn Params) -> Result<(), AlgoAsn1Error>;

    fn update(&mut self, data: &[u8]) -> Result<(), AlgoAsn1Error>;

    // The signature value, to go into a BIT STRING or an OCTET STRING as the structure has it
    fn sign(&mut self) -> Result<Vec<u8>, AlgoAsn1Error>;

    // Ok(false) when the signature does not verify
    fn verify(&mut self, signature: &[u8]) -> Result<bool, AlgoAsn1Error>;
}
