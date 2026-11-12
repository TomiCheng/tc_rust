#[cfg(any(feature = "shake128", feature = "shake256"))]
use tc_keccak::ShakeDigest;

#[cfg(any(
    feature = "cshake128",
    feature = "cshake256",
    feature = "tuplehash128",
    feature = "tuplehash256",
))]
use super::init_xof::InitXof;
#[cfg(any(feature = "shake128", feature = "shake256"))]
use super::row::TcXof;
use super::row::row;
use crate::DefaultAlgoContext;
use crate::xof::XofEntry;

// The rows of SHAKE, cSHAKE and TupleHash, to give to DefaultAlgoBuilder::reg_xof. SHAKE is named
// as Bouncy Castle's DigestUtilities names it; the others after their XOFs, with no alias or OID

#[cfg(feature = "shake128")]
pub(super) fn shake128(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row(
        "SHAKE128",
        &["SHAKE-128"],
        &["2.16.840.1.101.3.4.2.11"],
        || Box::new(TcXof(ShakeDigest::new(128))),
    )
}

#[cfg(feature = "shake256")]
pub(super) fn shake256(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row(
        "SHAKE256",
        &["SHAKE-256"],
        &["2.16.840.1.101.3.4.2.12"],
        || Box::new(TcXof(ShakeDigest::new(256))),
    )
}

#[cfg(feature = "cshake128")]
pub(super) fn cshake128(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("CSHAKE128", &[], &[], || {
        Box::new(InitXof::new(
            tc_keccak::CShakeDigest::new(128, b"", b""),
            |params: &crate::params::CShakeParams| {
                Ok(tc_keccak::CShakeDigest::new(
                    128,
                    params.function_name(),
                    params.customization(),
                ))
            },
        ))
    })
}

#[cfg(feature = "cshake256")]
pub(super) fn cshake256(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("CSHAKE256", &[], &[], || {
        Box::new(InitXof::new(
            tc_keccak::CShakeDigest::new(256, b"", b""),
            |params: &crate::params::CShakeParams| {
                Ok(tc_keccak::CShakeDigest::new(
                    256,
                    params.function_name(),
                    params.customization(),
                ))
            },
        ))
    })
}

// TupleHash with an empty customization until init sets one. Each update is one element of the
// tuple, as in Bouncy Castle, so a message in two updates is another tuple than in one

#[cfg(feature = "tuplehash128")]
pub(super) fn tuplehash128(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("TUPLEHASH128", &[], &[], || {
        Box::new(InitXof::new(
            tc_keccak::TupleHash::new(128, b""),
            |params: &crate::params::TupleHashParams| {
                Ok(tc_keccak::TupleHash::new(128, params.customization()))
            },
        ))
    })
}

#[cfg(feature = "tuplehash256")]
pub(super) fn tuplehash256(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("TUPLEHASH256", &[], &[], || {
        Box::new(InitXof::new(
            tc_keccak::TupleHash::new(256, b""),
            |params: &crate::params::TupleHashParams| {
                Ok(tc_keccak::TupleHash::new(256, params.customization()))
            },
        ))
    })
}

#[cfg(all(test, feature = "shake256"))]
mod tests {
    use core::any::Any;

    use crate::xof::Xof;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    const NAME: &str = "SHAKE256";

    // The first 64 bytes for the message "abc", from the NIST examples
    const ABC: &str = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
                       d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";
    // The same for the empty message
    const EMPTY: &str = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
                         d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn xof() -> Box<dyn Xof> {
        let algo = DefaultAlgoBuilder::default().build();
        algo.xof().get_by_name(NAME).unwrap()
    }

    #[test]
    fn the_helpers_give_the_standard_output_by_name_alias_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        let xofs = algo.xof();

        for name in ["SHAKE256", "shake-256"] {
            let output = xofs.calculate_by_name(name, b"abc", 64).unwrap();
            assert_eq!(hex(&output), ABC);
        }

        let oid = "2.16.840.1.101.3.4.2.12".parse().unwrap();
        let output = xofs.calculate_by_oid(&oid, b"abc", 64).unwrap();
        assert_eq!(hex(&output), ABC);

        let output = xofs.calculate_by_name(NAME, b"", 64).unwrap();
        assert_eq!(hex(&output), EMPTY);
    }

    #[test]
    fn a_shorter_output_is_the_start_of_a_longer_one() {
        let algo = DefaultAlgoBuilder::default().build();
        let output = algo.xof().calculate_by_name(NAME, b"abc", 10).unwrap();
        assert_eq!(hex(&output), ABC[..20]);
    }

    #[test]
    fn the_message_and_the_output_can_come_in_pieces() {
        let mut xof = xof();
        xof.update(b"a");
        xof.update(b"bc");

        let mut first = [0; 20];
        let mut second = [0; 12];
        assert_eq!(xof.output(&mut first), 20);
        assert_eq!(xof.output(&mut second), 12);
        let rest = xof.finalize_len(32);

        let output = [&first[..], &second[..], &rest[..]].concat();
        assert_eq!(hex(&output), ABC);
    }

    #[test]
    #[should_panic(expected = "attempt to absorb while squeezing")]
    fn update_panics_once_output_has_begun() {
        let mut xof = xof();
        xof.update(b"abc");
        xof.output(&mut [0; 1]);
        xof.update(b"more");
    }

    #[test]
    fn finalize_len_and_reset_start_the_next_message() {
        let mut xof = xof();
        xof.update(b"abc");
        xof.output(&mut [0; 1]);
        xof.finalize_len(1);

        xof.update(b"abc");
        assert_eq!(hex(&xof.finalize_len(64)), ABC);

        xof.update(b"other");
        xof.output(&mut [0; 1]);
        xof.reset();
        xof.update(b"abc");
        assert_eq!(hex(&xof.finalize_len(64)), ABC);
    }

    #[test]
    fn output_final_fills_the_output_and_starts_the_next_message() {
        let mut xof = xof();
        xof.update(b"abc");
        let mut output = [0; 64];
        assert_eq!(xof.output_final(&mut output), 64);
        assert_eq!(hex(&output), ABC);

        assert_eq!(xof.output_final(&mut output), 64);
        assert_eq!(hex(&output), EMPTY);
    }

    #[test]
    fn as_a_digest_it_gives_its_digest_size_of_output() {
        let mut xof = xof();
        assert_eq!(xof.digest_size(), 64);
        assert_eq!(xof.byte_length(), 136);

        xof.update_byte(b'a');
        xof.update(b"bc");
        assert_eq!(hex(&xof.finalize()), ABC);

        xof.update(b"abc");
        let mut output = [0; 64];
        assert_eq!(xof.do_final(&mut output).unwrap(), 64);
        assert_eq!(hex(&output), ABC);
    }

    struct OtherParams;

    impl Params for OtherParams {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn it_has_nothing_to_set_so_init_refuses_any_params() {
        let error = xof().init(&OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}

#[cfg(all(test, feature = "shake128"))]
mod shake128_tests {
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    // The first 32 bytes of SHAKE128 for the message "abc", from the NIST examples
    const ABC: &str = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8";

    #[test]
    fn shake128_gives_the_standard_output_by_name_alias_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        let oid = "2.16.840.1.101.3.4.2.11".parse().unwrap();
        for output in [
            algo.xof()
                .calculate_by_name("SHAKE128", b"abc", 32)
                .unwrap(),
            algo.xof()
                .calculate_by_name("SHAKE-128", b"abc", 32)
                .unwrap(),
            algo.xof().calculate_by_oid(&oid, b"abc", 32).unwrap(),
        ] {
            let hex: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, ABC);
        }
    }
}

#[cfg(all(
    test,
    any(
        feature = "cshake128",
        feature = "cshake256",
        feature = "tuplehash128",
        feature = "tuplehash256",
    )
))]
mod init_tests {
    use crate::xof::Xof;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn xof(name: &str) -> Box<dyn Xof> {
        let algo = DefaultAlgoBuilder::default().build();
        algo.xof().get_by_name(name).unwrap()
    }

    fn output(xof: &mut dyn Xof, parts: &[&[u8]]) -> Vec<u8> {
        for part in parts {
            xof.update(part);
        }
        xof.finalize_len(48)
    }

    fn direct(mut xof: impl tc_digest::Xof, parts: &[&[u8]]) -> Vec<u8> {
        for part in parts {
            xof.update(part);
        }
        let mut output = vec![0; 48];
        xof.output_final(&mut output);
        output
    }

    #[cfg(feature = "cshake128")]
    #[test]
    fn cshake_is_shake_until_init_sets_its_strings_which_reset_keeps() {
        use crate::params::CShakeParams;

        let mut cshake = xof("CSHAKE128");
        assert_eq!(
            output(cshake.as_mut(), &[b"abc"]),
            direct(tc_keccak::ShakeDigest::new(128), &[b"abc"])
        );

        let params = CShakeParams::new()
            .with_function_name(b"N".to_vec())
            .with_customization(b"Email Signature".to_vec());
        cshake.init(&params).unwrap();
        let expected = direct(
            tc_keccak::CShakeDigest::new(128, b"N", b"Email Signature"),
            &[b"abc"],
        );
        assert_eq!(output(cshake.as_mut(), &[b"abc"]), expected);

        cshake.update(b"other");
        cshake.reset();
        assert_eq!(output(cshake.as_mut(), &[b"abc"]), expected);
    }

    #[cfg(feature = "cshake128")]
    #[test]
    fn init_with_params_of_another_type_is_invalid_params() {
        use core::any::Any;

        use crate::{ErrorKind, Params};

        struct OtherParams;

        impl Params for OtherParams {
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let error = xof("CSHAKE128").init(&OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[cfg(feature = "cshake256")]
    #[test]
    fn cshake256_takes_its_strings_from_init() {
        use crate::params::CShakeParams;

        let mut cshake = xof("CSHAKE256");
        let params = CShakeParams::new().with_customization(b"S".to_vec());
        cshake.init(&params).unwrap();
        assert_eq!(
            output(cshake.as_mut(), &[b"abc"]),
            direct(tc_keccak::CShakeDigest::new(256, b"", b"S"), &[b"abc"])
        );
    }

    #[cfg(feature = "tuplehash128")]
    #[test]
    fn tuplehash128_takes_its_customization_from_init() {
        use crate::params::TupleHashParams;

        let mut tuple_hash = xof("TUPLEHASH128");
        let params = TupleHashParams::new().with_customization(b"S".to_vec());
        tuple_hash.init(&params).unwrap();
        assert_eq!(
            output(tuple_hash.as_mut(), &[b"ab", b"c"]),
            direct(tc_keccak::TupleHash::new(128, b"S"), &[b"ab", b"c"])
        );
    }

    #[cfg(feature = "tuplehash256")]
    #[test]
    fn each_update_of_tuplehash_is_one_element_of_the_tuple() {
        use crate::params::TupleHashParams;

        let mut tuple_hash = xof("TUPLEHASH256");
        let params = TupleHashParams::new().with_customization(b"My Tuple App".to_vec());
        tuple_hash.init(&params).unwrap();
        let two = output(tuple_hash.as_mut(), &[b"ab", b"c"]);
        assert_eq!(
            two,
            direct(
                tc_keccak::TupleHash::new(256, b"My Tuple App"),
                &[b"ab", b"c"]
            )
        );
        assert_ne!(two, output(tuple_hash.as_mut(), &[b"abc"]));
    }
}
