use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;
use tc_asym_cipher::KeyPairGeneratorInit;
use tc_rsa::{RsaKeyGenerationParams, RsaKeyGenerator};

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry};
use crate::params::RsaKeyGenParams;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of RSA, to give to DefaultAlgoBuilder::reg_key_pair_generator. Its name and OID are those
// of Bouncy Castle's GeneratorUtilities
pub(super) fn rsa(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![Box::new(Row {
        oids: vec![
            "1.2.840.113549.1.1.1"
                .parse()
                .expect("rsaEncryption is a valid OID"),
        ],
        rand: context.rand(),
    })]
}

struct Row {
    oids: Vec<Asn1Oid>,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "RSA"
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(Rsa {
            rand: (self.rand)(),
            params: None,
        })
    }
}

// Its params are an RsaKeyGenParams, and the keys draw from DefaultAlgoBuilder's random source
struct Rsa {
    rand: Box<dyn CryptoRng>,
    params: Option<RsaKeyGenParams>,
}

fn generator(
    rand: &mut dyn CryptoRng,
    settings: RsaKeyGenParams,
) -> Result<RsaKeyGenerator<&mut dyn CryptoRng>, AlgoError> {
    let params = RsaKeyGenerationParams::new()
        .with_public_exponent(settings.public_exponent())
        .with_strength(settings.strength())
        .with_certainty(settings.certainty());
    let mut generator = RsaKeyGenerator::new(rand);
    generator
        .init(&params)
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
    Ok(generator)
}

impl tc_asym_cipher::KeyPairGenerator for Rsa {
    type PublicKey = Box<dyn Params>;
    type PrivateKey = Box<dyn Params>;
    type Error = AlgoError;

    fn generate_key_pair(&mut self) -> Result<(Box<dyn Params>, Box<dyn Params>), AlgoError> {
        let params = self
            .params
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        let (public, private) = generator(self.rand.as_mut(), params)?
            .generate_key_pair()
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        Ok((Box::new(public), Box::new(private)))
    }
}

impl tc_asym_cipher::KeyPairGeneratorInit<dyn Params> for Rsa {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.params = None;
        let params = params
            .as_any()
            .downcast_ref::<RsaKeyGenParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        // tc_rsa judges the values when it is initialized, so that a bad one shows here
        generator(self.rand.as_mut(), *params)?;
        self.params = Some(*params);
        Ok(())
    }
}

impl KeyPairGenerator for Rsa {}

#[cfg(test)]
mod tests {
    use core::any::Any;
    use core::convert::Infallible;

    use rand_core::{CryptoRng, TryCryptoRng, TryRng};
    use tc_asym_cipher::AsymmetricKeyParams;
    use tc_rsa::{RsaKey, RsaKeyParams};

    use crate::generate::KeyPairGenerator;
    use crate::params::RsaKeyGenParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    const NAME: &str = "RSA";

    // Small, since generating the primes is slow
    fn params() -> RsaKeyGenParams {
        RsaKeyGenParams::new(1024)
    }

    fn generator() -> Box<dyn KeyPairGenerator> {
        let algo = DefaultAlgoBuilder::default().build();
        algo.key_pair_generator().get_by_name(NAME).unwrap()
    }

    fn rsa_key(key: &dyn Params) -> &RsaKey {
        key.as_any().downcast_ref::<RsaKey>().expect("an RsaKey")
    }

    #[test]
    fn the_helper_generates_a_public_and_a_private_key_of_one_modulus() {
        let algo = DefaultAlgoBuilder::default().build();
        let pair = algo
            .key_pair_generator()
            .generate_by_name_with(NAME, &params())
            .unwrap();

        let public = rsa_key(pair.public());
        let private = rsa_key(pair.private());
        assert!(!public.is_private_key());
        assert!(private.is_private_key());
        assert_eq!(public.modulus(), private.modulus());
        assert_eq!(public.modulus().bits(), 1024);
    }

    #[test]
    fn the_row_is_found_by_its_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        let oid = "1.2.840.113549.1.1.1".parse().unwrap();
        assert!(algo.key_pair_generator().get_by_oid(&oid).is_ok());
    }

    #[test]
    fn generate_needs_an_init_that_succeeded() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .key_pair_generator()
            .generate_by_name(NAME)
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        let mut generator = generator();
        let even_exponent = params().with_public_exponent(4);
        assert!(generator.init(&even_exponent).is_err());
        let error = generator.generate().err().unwrap();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn init_refuses_params_of_another_type_or_values_tc_rsa_refuses() {
        let mut generator = generator();
        let error = generator.init(&OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        for bad in [
            params().with_public_exponent(4),
            RsaKeyGenParams::new(8),
            params().with_certainty(0),
        ] {
            let error = generator.init(&bad).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams);
        }
    }

    // SplitMix64: the same seed gives the same numbers
    struct Seeded(u64);

    impl TryRng for Seeded {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            Ok(z ^ (z >> 31))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for Seeded {}

    fn seeded() -> Box<dyn CryptoRng> {
        Box::new(Seeded(1))
    }

    #[test]
    fn the_keys_draw_from_the_builders_random_source() {
        let mut builder = DefaultAlgoBuilder::default();
        builder.set_rand(seeded);
        let algo = builder.build();
        let generators = algo.key_pair_generator();

        let first = generators.generate_by_name_with(NAME, &params()).unwrap();
        let second = generators.generate_by_name_with(NAME, &params()).unwrap();
        assert_eq!(
            rsa_key(first.public()).modulus(),
            rsa_key(second.public()).modulus()
        );
    }
}
