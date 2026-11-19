use tc_algo::AlgoError;
use tc_openpgp::operator::params::generate::RsaKeyGenParams;
use tc_openpgp::{DefaultPgpOperatorBuilder, PgpOperatorBuilder};
use tc_openpgp_packet::PublicKeyAlgorithmTag;

fn main() -> Result<(), AlgoError> {
    let operator = DefaultPgpOperatorBuilder::default().build();
    let mut generator = operator
        .key_pair_generator()
        .get_by_algorithm(PublicKeyAlgorithmTag::RsaGeneral)?;
    let (public, _private) = generator.generate(&RsaKeyGenParams::new(3072))?;
    println!("Generated a 3072-bit {:?} key pair", public.algorithm());
    Ok(())
}
