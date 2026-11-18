use tc_asym_cipher::{KeyPairGenerator as _, KeyPairGeneratorInit as _};

use super::with_params::{Row, invalid_params, refuse};
use crate::DefaultAlgoContext;
use crate::generate::KeyPairGeneratorEntry;

// The key pair generators of the agreements over a fixed curve, X25519 and X448 of RFC 7748, with
// the names and OIDs of Bouncy Castle's GeneratorUtilities. They take no params
pub(super) fn agreement_keys(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    let rand = context.rand();
    let mut rows: Vec<Box<dyn KeyPairGeneratorEntry>> = Vec::new();

    #[cfg(feature = "cfrg-curves")]
    rows.push(Box::new(
        Row::<()>::new("X25519", &[], &["1.3.101.110"], rand, refuse, |rand, ()| {
            let mut generator = tc_cfrg_curves::X25519KeyPairGenerator::new(rand);
            generator
                .init(&tc_cfrg_curves::KeyGenerationParams::new())
                .map_err(invalid_params)?;
            let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
            Ok((Box::new(public), Box::new(private)))
        })
        .with_default(|| ()),
    ));
    #[cfg(feature = "cfrg-curves")]
    rows.push(Box::new(
        Row::<()>::new("X448", &[], &["1.3.101.111"], rand, refuse, |rand, ()| {
            let mut generator = tc_cfrg_curves::X448KeyPairGenerator::new(rand);
            generator
                .init(&tc_cfrg_curves::KeyGenerationParams::new())
                .map_err(invalid_params)?;
            let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
            Ok((Box::new(public), Box::new(private)))
        })
        .with_default(|| ()),
    ));

    rows
}

#[cfg(test)]
mod tests {
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn agreed(name: &str) {
        let algo = DefaultAlgoBuilder::default().build();
        let alice = algo.key_pair_generator().generate_by_name(name).unwrap();
        let bob = algo.key_pair_generator().generate_by_name(name).unwrap();
        let secret = |private, public| {
            let mut agreement = algo.agreement().get_by_name(name).unwrap();
            agreement.init(private).unwrap();
            let mut secret = vec![0; agreement.agreement_size()];
            agreement.calculate_agreement(public, &mut secret).unwrap();
            secret
        };
        assert_eq!(
            secret(alice.private(), bob.public()),
            secret(bob.private(), alice.public())
        );
    }

    #[cfg(feature = "cfrg-curves")]
    #[test]
    fn generated_x25519_pairs_reach_one_secret() {
        agreed("X25519");
    }

    #[cfg(feature = "cfrg-curves")]
    #[test]
    fn generated_x448_pairs_reach_one_secret() {
        agreed("X448");
    }
}
