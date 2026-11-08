use core::convert::Infallible;

use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_drbg::{Drbg as _, DrbgError, HmacDrbg};
use tc_macs::Hmac;
use tc_sha::Sha256Digest;

use crate::drbg::{Drbg, DrbgEntry};
use crate::params::DrbgParams;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The strength SHA-256 gives, and entropy and a nonce of the sizes SP 800-90A asks for it
const SECURITY_STRENGTH: usize = 256;
const ENTROPY_BYTES: usize = 32;
const NONCE_BYTES: usize = 16;

// The most tc_drbg gives in one request, 2^18 bits; a longer output is asked for in pieces
const MAX_REQUEST_BYTES: usize = (1 << 18) / 8;

// The row of HMAC_DRBG over SHA-256, to give to DefaultAlgoBuilder::reg_drbg. Its entropy and its
// nonce come from DefaultAlgoBuilder's random source
pub(super) fn hmac_sha256(context: &DefaultAlgoContext) -> Vec<Box<dyn DrbgEntry>> {
    vec![Box::new(Row {
        aliases: vec!["HMAC/SHA256".to_string()],
        rand: context.rand(),
    })]
}

struct Row {
    aliases: Vec<String>,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "HMAC/SHA-256"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

impl DrbgEntry for Row {
    fn create(&self) -> Box<dyn Drbg> {
        let mut rand = (self.rand)();
        let drbg = instantiate(rand.as_mut(), &[], &[]).expect("fixed sizes SHA-256 supports");
        Box::new(HmacSha256 { drbg, rand })
    }
}

type Generator = HmacDrbg<Hmac<Sha256Digest>>;

// An empty nonce is drawn from the random source
fn instantiate(
    rand: &mut dyn CryptoRng,
    nonce: &[u8],
    personalization: &[u8],
) -> Result<Generator, DrbgError> {
    let mut drawn = [0; NONCE_BYTES];
    let nonce = if nonce.is_empty() {
        rand.fill_bytes(&mut drawn);
        &drawn[..]
    } else {
        nonce
    };
    HmacDrbg::new(
        Hmac::new(Sha256Digest::new()),
        SECURITY_STRENGTH,
        ENTROPY_BYTES,
        rand,
        nonce,
        personalization,
    )
}

struct HmacSha256 {
    drbg: Generator,
    rand: Box<dyn CryptoRng>,
}

impl HmacSha256 {
    // Asks in pieces tc_drbg takes, and reseeds when it must, as Bouncy Castle's SP800SecureRandom
    // does. Neither other error can happen with the sizes fixed here
    fn generate(&mut self, output: &mut [u8]) {
        for piece in output.chunks_mut(MAX_REQUEST_BYTES) {
            match self.drbg.generate(piece, &[]) {
                Ok(()) => {}
                Err(DrbgError::ReseedRequired) => {
                    self.drbg
                        .reseed(self.rand.as_mut(), &[])
                        .expect("HMAC over SHA-256 does not fail");
                    self.drbg
                        .generate(piece, &[])
                        .expect("a reseeded generator gives a piece of this size");
                }
                Err(error) => panic!("HMAC_DRBG failed: {error}"),
            }
        }
    }
}

impl TryRng for HmacSha256 {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.generate(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.generate(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.generate(dest);
        Ok(())
    }
}

impl TryCryptoRng for HmacSha256 {}

impl Drbg for HmacSha256 {
    // Starts over from new entropy, with the nonce and the personalization string of the params
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<DrbgParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.drbg = instantiate(self.rand.as_mut(), params.nonce(), params.personalization())
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        Ok(())
    }

    fn reseed(&mut self, additional_input: &[u8]) -> Result<(), AlgoError> {
        self.drbg
            .reseed(self.rand.as_mut(), additional_input)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

#[cfg(test)]
mod tests {
    use core::any::Any;
    use core::convert::Infallible;

    use rand_core::{CryptoRng, Rng, TryCryptoRng, TryRng};

    use crate::params::DrbgParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    const NAME: &str = "HMAC/SHA-256";

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

    fn seeded_algo() -> Box<dyn crate::Algo> {
        let mut builder = DefaultAlgoBuilder::default();
        builder.set_rand(seeded);
        builder.build()
    }

    #[test]
    fn the_row_is_found_by_its_name_and_its_alias() {
        let algo = DefaultAlgoBuilder::default().build();
        assert!(algo.drbg().get_by_name(NAME).is_ok());
        assert!(algo.drbg().get_by_name("hmac/sha256").is_ok());
    }

    #[test]
    fn the_same_random_source_gives_the_same_output_and_another_seed_does_not() {
        let algo = seeded_algo();
        let mut first = algo.drbg().get_by_name(NAME).unwrap();
        let mut second = algo.drbg().get_by_name(NAME).unwrap();
        assert_eq!(first.next_u64(), second.next_u64());

        let mut other = DefaultAlgoBuilder::default()
            .build()
            .drbg()
            .get_by_name(NAME)
            .unwrap();
        assert_ne!(first.next_u64(), other.next_u64());
    }

    #[test]
    fn an_output_longer_than_one_request_is_given_in_full() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut drbg = algo.drbg().get_by_name(NAME).unwrap();

        let mut output = vec![0; 3 * super::MAX_REQUEST_BYTES + 5];
        drbg.fill_bytes(&mut output);
        let tail = &output[output.len() - 64..];
        assert!(tail.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn init_and_reseed_change_what_comes_next() {
        let algo = seeded_algo();
        let mut plain = algo.drbg().get_by_name(NAME).unwrap();
        let mut personalized = algo.drbg().get_by_name(NAME).unwrap();
        personalized
            .init(&DrbgParams::new().with_personalization(b"my app".to_vec()))
            .unwrap();
        assert_ne!(plain.next_u64(), personalized.next_u64());

        let mut kept = algo.drbg().get_by_name(NAME).unwrap();
        let mut reseeded = algo.drbg().get_by_name(NAME).unwrap();
        reseeded.reseed(b"extra").unwrap();
        assert_ne!(kept.next_u64(), reseeded.next_u64());
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn init_refuses_params_of_another_type() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut drbg = algo.drbg().get_by_name(NAME).unwrap();

        let error = drbg.init(&OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
