use tc_algo::AlgoError;
use tc_openpgp_packet::PublicKeyAlgorithmTag;

use super::PgpKeyPairGenerator;

/// Looks up registered generators by their OpenPGP algorithm tag.
pub trait PgpKeyPairGeneratorProvider: Send + Sync {
    fn get_by_algorithm(
        &self,
        tag: PublicKeyAlgorithmTag,
    ) -> Result<Box<dyn PgpKeyPairGenerator>, AlgoError>;
}
