use tc_algo_v2::generate::KeyPairGeneratorProvider;

pub trait X509Operator: Send + Sync {
    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider;
}
