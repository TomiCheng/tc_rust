#![allow(
    dead_code,
    reason = "a wrap feature on without its ciphers has no rows"
)]

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, InitError};

use super::row::{RowWrap, WrapKey, WrapKeyWithIv, row};
use crate::DefaultAlgoContext;
use crate::wrap::{Wrapper, WrapperEntry};

// An engine a wrap takes: keyed by WrapKey or WrapKeyWithIv through KeyParams
pub(super) trait Engine:
    BlockCipher<Error = BlockError>
    + BlockCipherInit<WrapKey, Error = InitError>
    + BlockCipherInit<WrapKeyWithIv, Error = InitError>
    + Send
    + 'static
{
}

impl<E> Engine for E where
    E: BlockCipher<Error = BlockError>
        + BlockCipherInit<WrapKey, Error = InitError>
        + BlockCipherInit<WrapKeyWithIv, Error = InitError>
        + Send
        + 'static
{
}

// The wraps of Bouncy Castle's WrapperUtilities, by their names, aliases and OIDs: RFC 3394 over
// AES, ARIA, Camellia and SEED, RFC 5649 over AES and ARIA, and RFC 3211 over AES, ARIA, Camellia,
// DES and DESede. A row needs the feature of its wrap and of its cipher
pub(super) fn block(context: &DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>> {
    #[allow(unused_mut, reason = "empty when no cipher is on")]
    let mut rows: Vec<Box<dyn WrapperEntry>> = Vec::new();
    #[allow(unused_variables, reason = "only RFC 3211 draws randomness")]
    let rand = context.rand();

    #[cfg(feature = "key-wrap")]
    {
        #[cfg(feature = "aes")]
        rows.push(rfc3394(
            "AESWRAP",
            &["AESKW"],
            &[
                "2.16.840.1.101.3.4.1.5",
                "2.16.840.1.101.3.4.1.25",
                "2.16.840.1.101.3.4.1.45",
            ],
            tc_aes::AesEngine::new,
        ));
        #[cfg(feature = "aria")]
        rows.push(rfc3394(
            "ARIAWRAP",
            &["ARIAKW"],
            &[
                "1.2.410.200046.1.1.40",
                "1.2.410.200046.1.1.41",
                "1.2.410.200046.1.1.42",
            ],
            tc_aria::AriaEngine::new,
        ));
        #[cfg(feature = "camellia")]
        rows.push(rfc3394(
            "CAMELLIAWRAP",
            &[],
            &[
                "1.2.392.200011.61.1.1.3.2",
                "1.2.392.200011.61.1.1.3.3",
                "1.2.392.200011.61.1.1.3.4",
            ],
            tc_camellia::CamelliaEngine::new,
        ));
        #[cfg(feature = "seed")]
        rows.push(rfc3394(
            "SEEDWRAP",
            &["SEEDKW"],
            &["1.2.410.200004.7.1.1.1"],
            tc_seed::SeedEngine::new,
        ));
    }
    #[cfg(feature = "key-wrap")]
    {
        #[cfg(feature = "aes")]
        rows.push(rfc5649(
            "AESWRAPPAD",
            &["AESKWP", "AESRFC5649WRAP"],
            &[
                "2.16.840.1.101.3.4.1.8",
                "2.16.840.1.101.3.4.1.28",
                "2.16.840.1.101.3.4.1.48",
            ],
            tc_aes::AesEngine::new,
        ));
        #[cfg(feature = "aria")]
        rows.push(rfc5649(
            "ARIAWRAPPAD",
            &["ARIAKWP"],
            &[
                "1.2.410.200046.1.1.43",
                "1.2.410.200046.1.1.44",
                "1.2.410.200046.1.1.45",
            ],
            tc_aria::AriaEngine::new,
        ));
    }
    #[cfg(feature = "key-wrap")]
    {
        #[cfg(feature = "aes")]
        rows.push(rfc3211("AESRFC3211WRAP", tc_aes::AesEngine::new, rand));
        #[cfg(feature = "aria")]
        rows.push(rfc3211("ARIARFC3211WRAP", tc_aria::AriaEngine::new, rand));
        #[cfg(feature = "camellia")]
        rows.push(rfc3211(
            "CAMELLIARFC3211WRAP",
            tc_camellia::CamelliaEngine::new,
            rand,
        ));
        #[cfg(feature = "des")]
        rows.push(rfc3211("DESRFC3211WRAP", tc_des::DesEngine::new, rand));
        #[cfg(feature = "des")]
        rows.push(rfc3211(
            "DESEDERFC3211WRAP",
            tc_des::DesEdeEngine::new,
            rand,
        ));
    }

    rows
}

// RFC 3394, with the standard IV unless the params have one
#[cfg(feature = "key-wrap")]
fn rfc3394<E: Engine>(
    name: &str,
    aliases: &[&str],
    oids: &[&str],
    engine: fn() -> E,
) -> Box<dyn WrapperEntry> {
    row(
        name,
        aliases,
        oids,
        Box::new(move || -> Box<dyn Wrapper> {
            Box::new(RowWrap::<_, WrapKey>::new(
                tc_key_wrap::Rfc3394WrapEngine::new(engine()),
            ))
        }),
    )
}

// RFC 5649, a key of any length, with the standard IV unless the params have one
#[cfg(feature = "key-wrap")]
fn rfc5649<E: Engine>(
    name: &str,
    aliases: &[&str],
    oids: &[&str],
    engine: fn() -> E,
) -> Box<dyn WrapperEntry> {
    row(
        name,
        aliases,
        oids,
        Box::new(move || -> Box<dyn Wrapper> {
            Box::new(RowWrap::<_, WrapKey>::new(
                tc_key_wrap::Rfc5649WrapEngine::new(engine()),
            ))
        }),
    )
}

// RFC 3211, the password-based key wrap of CMS, which needs an IV and pads with random bytes
#[cfg(feature = "key-wrap")]
fn rfc3211<E: Engine>(
    name: &str,
    engine: fn() -> E,
    rand: fn() -> Box<dyn rand_core::CryptoRng>,
) -> Box<dyn WrapperEntry> {
    row(
        name,
        &[],
        &[],
        Box::new(move || -> Box<dyn Wrapper> {
            Box::new(RowWrap::<_, WrapKeyWithIv>::new(
                tc_key_wrap::Rfc3211WrapEngine::new(engine(), rand()),
            ))
        }),
    )
}

#[cfg(all(test, feature = "key-wrap", feature = "aes"))]
mod tests {
    use core::any::Any;

    use crate::params::key::KeyOwned;
    use crate::wrap::{WrapDirection, Wrapper};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    const NAME: &str = "AESWRAP";

    // RFC 3394, section 4.1
    const KEK: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const WRAPPED: [u8; 24] = [
        0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b,
        0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
    ];

    // RFC 3394, section 4.6
    const WRAPPED_BY_256_BITS: [u8; 40] = [
        0x28, 0xc9, 0xf4, 0x04, 0xc4, 0xb8, 0x10, 0xf4, 0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87, 0xf8,
        0x26, 0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26, 0xcb, 0xc7, 0xf0, 0xe7, 0x1a, 0x99,
        0xf4, 0x3b, 0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21,
    ];

    fn kek() -> KeyOwned {
        KeyOwned::new(KEK.to_vec())
    }

    fn wrapper() -> Box<dyn Wrapper> {
        let algo = DefaultAlgoBuilder::default().build();
        algo.wrap().get_by_name(NAME).unwrap()
    }

    #[test]
    fn the_helpers_give_the_standard_output_by_name_alias_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        let wrappers = algo.wrap();

        for name in ["AESWRAP", "aeskw"] {
            assert_eq!(wrappers.wrap_by_name(name, &kek(), &KEY).unwrap(), WRAPPED);
            assert_eq!(
                wrappers.unwrap_by_name(name, &kek(), &WRAPPED).unwrap(),
                KEY
            );
        }

        let oid = "2.16.840.1.101.3.4.1.5".parse().unwrap();
        assert_eq!(wrappers.wrap_by_oid(&oid, &kek(), &KEY).unwrap(), WRAPPED);
        assert_eq!(wrappers.unwrap_by_oid(&oid, &kek(), &WRAPPED).unwrap(), KEY);
    }

    #[test]
    fn a_longer_kek_wraps_a_longer_key_to_the_standard_output() {
        let algo = DefaultAlgoBuilder::default().build();
        let wrappers = algo.wrap();
        let kek = KeyOwned::new((0..32).collect());
        let key = [&KEY[..], &KEK[..]].concat();

        assert_eq!(
            wrappers.wrap_by_name(NAME, &kek, &key).unwrap(),
            WRAPPED_BY_256_BITS
        );
        assert_eq!(
            wrappers
                .unwrap_by_name(NAME, &kek, &WRAPPED_BY_256_BITS)
                .unwrap(),
            key
        );
    }

    #[test]
    fn a_generated_key_can_wrap() {
        let algo = DefaultAlgoBuilder::default().build();
        let kek = algo.key_generator().generate_by_name("AES256").unwrap();
        let kek = kek.as_ref();

        let wrapped = algo.wrap().wrap_by_name(NAME, kek, &KEY).unwrap();
        assert_eq!(wrapped.len(), KEY.len() + 8);
        assert_eq!(
            algo.wrap().unwrap_by_name(NAME, kek, &wrapped).unwrap(),
            KEY
        );
    }

    #[test]
    fn unwrap_refuses_a_changed_input_or_another_kek() {
        let algo = DefaultAlgoBuilder::default().build();
        let wrappers = algo.wrap();

        let mut changed = WRAPPED;
        changed[0] ^= 1;
        let error = wrappers.unwrap_by_name(NAME, &kek(), &changed).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);

        let other = KeyOwned::new(vec![0x42; 16]);
        let error = wrappers.unwrap_by_name(NAME, &other, &WRAPPED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn a_key_that_is_no_multiple_of_8_bytes_is_data_length() {
        let algo = DefaultAlgoBuilder::default().build();
        let error = algo
            .wrap()
            .wrap_by_name(NAME, &kek(), &KEY[..15])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn the_buffer_calls_give_the_standard_output() {
        let mut wrapper = wrapper();
        wrapper.init(WrapDirection::Wrap, &kek()).unwrap();
        assert_eq!(wrapper.wrapped_len(KEY.len()).unwrap(), WRAPPED.len());
        let mut wrapped = [0; 24];
        assert_eq!(wrapper.wrap_into(&KEY, &mut wrapped).unwrap(), 24);
        assert_eq!(wrapped, WRAPPED);

        wrapper.init(WrapDirection::Unwrap, &kek()).unwrap();
        assert_eq!(wrapper.max_unwrapped_len(WRAPPED.len()).unwrap(), KEY.len());
        let mut key = [0; 16];
        assert_eq!(wrapper.unwrap_into(&WRAPPED, &mut key).unwrap(), 16);
        assert_eq!(key, KEY);
    }

    #[test]
    fn unwrap_into_leaves_no_key_in_the_output_when_the_check_fails() {
        let mut changed = WRAPPED;
        changed[0] ^= 1;

        let mut wrapper = wrapper();
        wrapper.init(WrapDirection::Unwrap, &kek()).unwrap();
        let mut key = [0; 16];
        let error = wrapper.unwrap_into(&changed, &mut key).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
        assert_eq!(key, [0; 16]);
    }

    #[test]
    fn an_output_too_short_is_data_length() {
        let mut wrapper = wrapper();
        wrapper.init(WrapDirection::Wrap, &kek()).unwrap();
        let error = wrapper.wrap_into(&KEY, &mut [0; 23]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);

        wrapper.init(WrapDirection::Unwrap, &kek()).unwrap();
        let error = wrapper.unwrap_into(&WRAPPED, &mut [0; 15]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
    }

    #[test]
    fn a_wrapper_works_only_in_the_direction_of_its_init() {
        let mut wrapper = wrapper();
        let error = wrapper.wrap(&KEY).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);

        wrapper.init(WrapDirection::Wrap, &kek()).unwrap();
        let error = wrapper.unwrap(&WRAPPED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn init_refuses_params_of_another_type_or_a_kek_of_the_wrong_length() {
        let mut wrapper = wrapper();

        let error = wrapper.init(WrapDirection::Wrap, &OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let short = KeyOwned::new(vec![0; 15]);
        let error = wrapper.init(WrapDirection::Wrap, &short).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(all(
    test,
    feature = "key-wrap",
    feature = "aes",
    feature = "aria",
    feature = "camellia",
    feature = "seed",
    feature = "des"
))]
mod family_tests {
    use crate::params::{cipher::KeyWithIvOwned, key::KeyOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    // RFC 5649, section 6
    #[test]
    fn aes_wrap_pad_gives_the_outputs_of_rfc_5649() {
        let algo = DefaultAlgoBuilder::default().build();
        let wrappers = algo.wrap();
        let kek = KeyOwned::new(unhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"));
        for (key, wrapped) in [
            (
                "c37b7e6492584340bed12207808941155068f738",
                "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
            ),
            ("466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"),
        ] {
            for name in ["AESWRAPPAD", "AESKWP", "AESRFC5649WRAP"] {
                assert_eq!(
                    wrappers.wrap_by_name(name, &kek, &unhex(key)).unwrap(),
                    unhex(wrapped)
                );
            }
            let oid = "2.16.840.1.101.3.4.1.28".parse().unwrap();
            assert_eq!(
                wrappers.unwrap_by_oid(&oid, &kek, &unhex(wrapped)).unwrap(),
                unhex(key)
            );
        }
    }

    // The standard IV, given or left out, gives the same output
    #[test]
    fn an_iv_given_to_rfc_3394_takes_the_place_of_the_standard_one() {
        let algo = DefaultAlgoBuilder::default().build();
        let wrappers = algo.wrap();
        let key = [0x11; 16];
        let standard = wrappers
            .wrap_by_name("AESWRAP", &KeyOwned::new(vec![7; 16]), &key)
            .unwrap();
        let given = KeyWithIvOwned::new(vec![7; 16], vec![0xa6; 8]);
        assert_eq!(
            wrappers.wrap_by_name("AESWRAP", &given, &key).unwrap(),
            standard
        );

        let other = KeyWithIvOwned::new(vec![7; 16], vec![1; 8]);
        let wrapped = wrappers.wrap_by_name("AESWRAP", &other, &key).unwrap();
        assert_ne!(wrapped, standard);
        assert_eq!(
            wrappers
                .unwrap_by_name("AESWRAP", &other, &wrapped)
                .unwrap(),
            key
        );
    }

    #[test]
    fn every_rfc_3394_and_5649_row_unwraps_what_it_wraps() {
        let algo = DefaultAlgoBuilder::default().build();
        let wrappers = algo.wrap();
        let key = [0x5a; 24];
        for (name, kek) in [
            ("ARIAWRAP", 16),
            ("ARIAKW", 32),
            ("CAMELLIAWRAP", 24),
            ("SEEDKW", 16),
            ("ARIAKWP", 16),
        ] {
            let kek = KeyOwned::new(vec![3; kek]);
            let wrapped = wrappers.wrap_by_name(name, &kek, &key).unwrap();
            assert_eq!(wrapped.len(), key.len() + 8, "{name}");
            assert_eq!(
                wrappers.unwrap_by_name(name, &kek, &wrapped).unwrap(),
                key,
                "{name}"
            );
        }
    }

    // RFC 3211 pads with random bytes, so only a round trip can be checked
    #[test]
    fn every_rfc_3211_row_unwraps_what_it_wraps_and_needs_an_iv() {
        let algo = DefaultAlgoBuilder::default().build();
        let wrappers = algo.wrap();
        let key = [0x5a; 16];
        for (name, kek, block) in [
            ("AESRFC3211WRAP", 16, 16),
            ("ARIARFC3211WRAP", 16, 16),
            ("CAMELLIARFC3211WRAP", 16, 16),
            ("DESRFC3211WRAP", 8, 8),
            ("DESEDERFC3211WRAP", 24, 8),
        ] {
            let params = KeyWithIvOwned::new(vec![3; kek], vec![9; block]);
            let wrapped = wrappers.wrap_by_name(name, &params, &key).unwrap();
            assert_eq!(
                wrappers.unwrap_by_name(name, &params, &wrapped).unwrap(),
                key,
                "{name}"
            );

            let error = wrappers
                .wrap_by_name(name, &KeyOwned::new(vec![3; kek]), &key)
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams, "{name}");
        }
    }
}
