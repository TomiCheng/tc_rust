use std::sync::Arc;

use tc_algo_v2::Params;
use tc_algo_v2::generate::KeyPairGeneratorProvider;

use crate::X509Error;
use crate::operator::signer::SignatureFactory;
use crate::operator::spki::SpkiProvider;

pub trait X509Operator: Send + Sync {
    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider;

    fn spki(&self) -> &dyn SpkiProvider;

    // A factory that signs with the private key under the named algorithm, such as
    // "SHA-256withRSA"; the case of the name does not matter. UnknownSigner when no row has the
    // name, and the error of the signer when it refuses the key. The factory holds the key, so an
    // Arc of it can be given to several factories
    fn signature_factory(
        &self,
        name: &str,
        private_key: Arc<dyn Params>,
    ) -> Result<Box<dyn SignatureFactory>, X509Error>;
}
