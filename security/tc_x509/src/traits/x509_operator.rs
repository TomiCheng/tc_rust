use tc_algo_v2::generate::KeyPairGeneratorProvider;

use crate::cert::X509CertificateV3Generator;

pub trait X509Operator: Send + Sync {
    fn key_pair_generator(&self) -> &dyn KeyPairGeneratorProvider;

    fn v3_cert_generator(&self) -> Box<dyn X509CertificateV3Generator>;
}
