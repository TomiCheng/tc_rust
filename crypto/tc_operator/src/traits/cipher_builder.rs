use std::io;

use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CipherWriter;

pub trait CipherBuilder {
    type Writer<W: io::Write>: CipherWriter<W>;
    type Error: core::error::Error + Send + Sync + 'static;

    fn algorithm(&self) -> &AlgorithmIdentifier;

    fn build_cipher<W: io::Write>(&self, output: W) -> Result<Self::Writer<W>, Self::Error>;
}
