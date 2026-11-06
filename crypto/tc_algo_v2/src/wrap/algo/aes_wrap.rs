use core::error::Error;

use tc_aes::AesEngine;
use tc_asn1::Asn1Oid;
use tc_key_wrap::{
    KeyWithIvOptRef, KeyWrap, KeyWrapError, KeyWrapInit, Rfc3394WrapEngine,
    WrapDirection as KeyWrapDirection,
};

use crate::{
    AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, KeyOwned, KeyParams, Params,
    WrapDirection, Wrapper, WrapperEntry,
};

// The row of AESWRAP, RFC 3394, to give to DefaultAlgoBuilder::reg_wrap. Its names and OIDs are
// those of Bouncy Castle's WrapperUtilities. Its params are a KeyOwned, so that a generated key can
// wrap, and it keeps to the standard IV
pub(super) fn aes_wrap(_context: &DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>> {
    vec![Box::new(Row {
        aliases: vec!["AESKW".to_string()],
        oids: vec![
            oid("2.16.840.1.101.3.4.1.5"),
            oid("2.16.840.1.101.3.4.1.25"),
            oid("2.16.840.1.101.3.4.1.45"),
        ],
    })]
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("a valid OID")
}

struct Row {
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "AESWRAP"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl WrapperEntry for Row {
    fn create(&self) -> Box<dyn Wrapper> {
        Box::new(AesWrap(Rfc3394WrapEngine::new(AesEngine::new())))
    }
}

struct AesWrap(Rfc3394WrapEngine<AesEngine>);

impl Wrapper for AesWrap {
    fn init(&mut self, direction: WrapDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<KeyOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        let direction = match direction {
            WrapDirection::Wrap => KeyWrapDirection::Wrap,
            WrapDirection::Unwrap => KeyWrapDirection::Unwrap,
        };
        self.0
            .init(direction, &KeyWithIvOptRef::new(key.key(), None))
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.wrapped_len(input_len).map_err(algo_error)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.max_unwrapped_len(input_len).map_err(algo_error)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.wrap_into(input, output).map_err(algo_error)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.unwrap_into(input, output).map_err(algo_error)
    }
}

fn algo_error<E: Error + Send + Sync + 'static>(error: KeyWrapError<E>) -> AlgoError {
    let kind = match error {
        KeyWrapError::NotInitialized
        | KeyWrapError::NotForWrapping
        | KeyWrapError::NotForUnwrapping => ErrorKind::NotInitialized,
        KeyWrapError::IntegrityCheckFailed => ErrorKind::InvalidCiphertext,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use core::any::Any;

    use crate::{
        AlgoBuilder, DefaultAlgoBuilder, ErrorKind, KeyOwned, Params, WrapDirection, Wrapper,
    };

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
