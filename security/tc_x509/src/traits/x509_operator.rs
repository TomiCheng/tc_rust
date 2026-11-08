use tc_algo_v2::generate::KeyPairGeneratorProvider;

use crate::operator::spki::SpkiProvider;

pub trait X509Operator: Send + Sync {
    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider;

    fn spki(&self) -> &dyn SpkiProvider;
}
