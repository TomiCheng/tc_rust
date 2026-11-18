use core::convert::Infallible;
use std::sync::Arc;

use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_drbg::DrbgError;

use crate::drbg::{Drbg, DrbgEntry};
use crate::params::DrbgParams;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The most this row asks for in one request: 2^18 bits, under the limit of every kind of SP 800-90A;
// a longer output is asked for in pieces
const MAX_REQUEST_BYTES: usize = (1 << 18) / 8;

// The digests SP 800-90A takes for HMAC_DRBG and Hash_DRBG, with the security strength each gives
#[cfg(feature = "drbg")]
const DIGESTS: &[(&str, usize)] = &[
    ("SHA-1", 128),
    ("SHA-224", 192),
    ("SHA-256", 256),
    ("SHA-384", 256),
    ("SHA-512", 256),
    ("SHA-512/224", 192),
    ("SHA-512/256", 256),
];

// A generator of tc_drbg, whose reseed takes any random source
trait Generator {
    fn generate(&mut self, output: &mut [u8]) -> Result<(), DrbgError>;
    fn reseed(
        &mut self,
        rand: &mut dyn CryptoRng,
        additional_input: &[u8],
    ) -> Result<(), DrbgError>;
}

impl<G: tc_drbg::Drbg> Generator for G {
    fn generate(&mut self, output: &mut [u8]) -> Result<(), DrbgError> {
        tc_drbg::Drbg::generate(self, output, &[])
    }

    fn reseed(
        &mut self,
        rand: &mut dyn CryptoRng,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        tc_drbg::Drbg::reseed(self, rand, additional_input)
    }
}

// Instantiates a generator of the row's kind: its entropy from the random source, with the nonce
// and the personalization string
type Instantiate = Arc<
    dyn Fn(&mut dyn CryptoRng, usize, &[u8], &[u8]) -> Result<Box<dyn Generator>, DrbgError>
        + Send
        + Sync,
>;

// The rows of the DRBGs of NIST SP 800-90A, to give to DefaultAlgoBuilder::reg_drbg: HMAC_DRBG and
// Hash_DRBG over each of its digests whose row is on, and CTR_DRBG over AES with the derivation
// function, as Bouncy Castle's SP800SecureRandomBuilder builds them. Each takes the most security
// strength its base gives, entropy of that many bits, and a nonce of half as many, from
// DefaultAlgoBuilder's random source
pub(super) fn sp800(context: &DefaultAlgoContext) -> Vec<Box<dyn DrbgEntry>> {
    #[allow(unused_mut, reason = "empty when no kind has its base")]
    let mut rows: Vec<Box<dyn DrbgEntry>> = Vec::new();
    #[allow(unused_variables, reason = "unused when no kind has its base")]
    let rand = context.rand();

    #[cfg(feature = "drbg")]
    for digest in crate::digest::BUILT_IN
        .iter()
        .flat_map(|create| create(context))
    {
        let Some(&(_, strength)) = DIGESTS.iter().find(|(name, _)| *name == digest.name()) else {
            continue;
        };
        let digest: Arc<dyn crate::digest::DigestEntry> = Arc::from(digest);
        let names = |kind: &str| -> (String, Vec<String>) {
            let name = format!("{kind}/{}", digest.name());
            let aliases = digest
                .aliases()
                .iter()
                .map(|alias| format!("{kind}/{alias}"))
                .collect();
            (name, aliases)
        };
        #[cfg(feature = "drbg")]
        {
            let (name, aliases) = names("HMAC");
            let digest = digest.clone();
            rows.push(row(
                name,
                aliases,
                strength,
                rand,
                Arc::new(move |rand, strength, nonce, personalization| {
                    let mac = tc_macs::Hmac::new(crate::digest::RowDigest::new(digest.clone()));
                    let generator = tc_drbg::HmacDrbg::new(
                        mac,
                        strength,
                        strength / 8,
                        rand,
                        nonce,
                        personalization,
                    )?;
                    Ok(Box::new(generator) as Box<dyn Generator>)
                }),
            ));
        }
        #[cfg(feature = "drbg")]
        {
            let (name, aliases) = names("HASH");
            let digest = digest.clone();
            rows.push(row(
                name,
                aliases,
                strength,
                rand,
                Arc::new(move |rand, strength, nonce, personalization| {
                    let generator = tc_drbg::HashDrbg::new(
                        crate::digest::RowDigest::new(digest.clone()),
                        strength,
                        strength / 8,
                        rand,
                        nonce,
                        personalization,
                    )?;
                    Ok(Box::new(generator) as Box<dyn Generator>)
                }),
            ));
        }
    }

    #[cfg(all(feature = "drbg", feature = "aes"))]
    for bits in [128, 192, 256] {
        rows.push(row(
            format!("CTR/AES-{bits}"),
            vec![format!("CTR/AES{bits}")],
            bits,
            rand,
            Arc::new(move |rand, strength, nonce, personalization| {
                let generator = tc_drbg::CtrDrbg::new_with_derivation_function(
                    tc_aes::AesEngine::new(),
                    bits,
                    strength,
                    strength / 8,
                    rand,
                    nonce,
                    personalization,
                )?;
                Ok(Box::new(generator) as Box<dyn Generator>)
            }),
        ));
    }

    rows
}

#[allow(dead_code, reason = "unused when no kind has its base")]
fn row(
    name: String,
    aliases: Vec<String>,
    strength: usize,
    rand: fn() -> Box<dyn CryptoRng>,
    instantiate: Instantiate,
) -> Box<dyn DrbgEntry> {
    Box::new(Row {
        name,
        aliases,
        strength,
        rand,
        instantiate,
    })
}

struct Row {
    name: String,
    aliases: Vec<String>,
    strength: usize,
    rand: fn() -> Box<dyn CryptoRng>,
    instantiate: Instantiate,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        &self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

impl DrbgEntry for Row {
    fn create(&self) -> Box<dyn Drbg> {
        let mut rand = (self.rand)();
        let generator = start(&self.instantiate, self.strength, rand.as_mut(), &[], &[])
            .expect("the sizes of the row are those its base takes");
        Box::new(RowDrbg {
            generator,
            rand,
            strength: self.strength,
            instantiate: self.instantiate.clone(),
        })
    }
}

// Instantiates, with a nonce of half the strength drawn from the random source when the given one
// is empty
fn start(
    instantiate: &Instantiate,
    strength: usize,
    rand: &mut dyn CryptoRng,
    nonce: &[u8],
    personalization: &[u8],
) -> Result<Box<dyn Generator>, DrbgError> {
    let mut drawn = vec![0; strength / 16];
    let nonce = if nonce.is_empty() {
        rand.fill_bytes(&mut drawn);
        &drawn[..]
    } else {
        nonce
    };
    instantiate(rand, strength, nonce, personalization)
}

struct RowDrbg {
    generator: Box<dyn Generator>,
    rand: Box<dyn CryptoRng>,
    strength: usize,
    instantiate: Instantiate,
}

impl RowDrbg {
    // Asks in pieces tc_drbg takes, and reseeds when it must, as Bouncy Castle's SP800SecureRandom
    // does. Neither other error can happen with the sizes fixed here
    fn generate(&mut self, output: &mut [u8]) {
        for piece in output.chunks_mut(MAX_REQUEST_BYTES) {
            match self.generator.generate(piece) {
                Ok(()) => {}
                Err(DrbgError::ReseedRequired) => {
                    self.generator
                        .reseed(self.rand.as_mut(), &[])
                        .expect("a reseed of the row's sizes does not fail");
                    self.generator
                        .generate(piece)
                        .expect("a reseeded generator gives a piece of this size");
                }
                Err(error) => panic!("the DRBG failed: {error}"),
            }
        }
    }
}

impl TryRng for RowDrbg {
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

impl TryCryptoRng for RowDrbg {}

impl Drbg for RowDrbg {
    // Starts over from new entropy, with the nonce and the personalization string of the params
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<DrbgParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.generator = start(
            &self.instantiate,
            self.strength,
            self.rand.as_mut(),
            params.nonce(),
            params.personalization(),
        )
        .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        Ok(())
    }

    fn reseed(&mut self, additional_input: &[u8]) -> Result<(), AlgoError> {
        self.generator
            .reseed(self.rand.as_mut(), additional_input)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

#[cfg(all(test, feature = "drbg", feature = "sha"))]
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

// The vectors of NIST CAVP, drbgvectors_no_reseed, COUNT = 0, through the rows: the entropy comes
// from the random source, the nonce from DrbgParams, and the second of two outputs is compared, as
// CAVP does
#[cfg(all(test, feature = "drbg", feature = "aes", feature = "sha"))]
mod cavp_tests {
    use core::convert::Infallible;

    use rand_core::{CryptoRng, Rng, TryCryptoRng, TryRng};

    use crate::params::DrbgParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    // A random source that gives the same entropy at each call, from its start
    struct Repeat(&'static [u8]);

    impl TryRng for Repeat {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            unreachable!("the rows draw bytes")
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            unreachable!("the rows draw bytes")
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
            for (byte, source) in dest.iter_mut().zip(self.0.iter().cycle()) {
                *byte = *source;
            }
            Ok(())
        }
    }

    impl TryCryptoRng for Repeat {}

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn second_output(rand: fn() -> Box<dyn CryptoRng>, name: &str, nonce: &str, expected: &str) {
        let mut builder = DefaultAlgoBuilder::default();
        builder.set_rand(rand);
        let mut drbg = builder.build().drbg().get_by_name(name).unwrap();
        drbg.init(&DrbgParams::new().with_nonce(hex(nonce)))
            .unwrap();
        let expected = hex(expected);
        let mut output = vec![0; expected.len()];
        drbg.fill_bytes(&mut output);
        drbg.fill_bytes(&mut output);
        assert_eq!(output, expected, "{name}");
    }

    #[test]
    fn hmac_sha256_gives_the_output_of_cavp() {
        second_output(
            || {
                Box::new(Repeat(&[
                    0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde, 0x1c, 0xbd,
                    0xc4, 0x6e, 0x68, 0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb, 0x93, 0x5e, 0xe2, 0x85,
                    0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88,
                ]))
            },
            "HMAC/SHA-256",
            "659ba96c601dc69fc902940805ec0ca8",
            "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
        );
    }

    #[test]
    fn hash_sha256_gives_the_output_of_cavp() {
        second_output(
            || {
                Box::new(Repeat(&[
                    0xa6, 0x5a, 0xd0, 0xf3, 0x45, 0xdb, 0x4e, 0x0e, 0xff, 0xe8, 0x75, 0xc3, 0xa2,
                    0xe7, 0x1f, 0x42, 0xc7, 0x12, 0x9d, 0x62, 0x0f, 0xf5, 0xc1, 0x19, 0xa9, 0xef,
                    0x55, 0xf0, 0x51, 0x85, 0xe0, 0xfb,
                ]))
            },
            "HASH/SHA256",
            "8581f9317517276e06e9607ddbcbcc2e",
            "d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df",
        );
    }

    #[test]
    fn ctr_aes128_gives_the_output_of_cavp() {
        second_output(
            || {
                Box::new(Repeat(&[
                    0x89, 0x0e, 0xb0, 0x67, 0xac, 0xf7, 0x38, 0x2e, 0xff, 0x80, 0xb0, 0xc7, 0x3b,
                    0xc8, 0x72, 0xc6,
                ]))
            },
            "CTR/AES-128",
            "aad471ef3ef1d203",
            "a5514ed7095f64f3d0d3a5760394ab42062f373a25072a6ea6bcfd8489e94af6cf18659fea22ed1ca0a9e33f718b115ee536b12809c31b72b08ddd8be1910fa3",
        );
    }

    #[test]
    fn every_kind_is_there_for_the_digests_of_sp_800_90a_alone() {
        let algo = DefaultAlgoBuilder::default().build();
        for name in ["HMAC/SHA-512", "HASH/SHA-512", "CTR/AES256", "ctr/aes-192"] {
            let mut drbg = algo.drbg().get_by_name(name).unwrap();
            assert_ne!(drbg.next_u64(), drbg.next_u64(), "{name}");
        }
        assert!(algo.drbg().get_by_name("HMAC/MD5").is_err());
    }
}
