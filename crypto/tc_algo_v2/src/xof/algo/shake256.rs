use tc_asn1::Asn1Oid;
use tc_digest::{Digest as _, Xof as _};
use tc_keccak::ShakeDigest;

use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Xof, XofEntry};

const BIT_LENGTH: usize = 256;

// The row of SHAKE256, to give to DefaultAlgoBuilder::reg_xof. Its names and OID are those of Bouncy
// Castle's DigestUtilities
pub(super) fn shake256(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    vec![Box::new(Row {
        aliases: vec!["SHAKE-256".to_string()],
        oids: vec![
            "2.16.840.1.101.3.4.2.12"
                .parse()
                .expect("id-shake256 is a valid OID"),
        ],
    })]
}

struct Row {
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "SHAKE256"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl XofEntry for Row {
    fn create(&self) -> Box<dyn Xof> {
        Box::new(Shake256 {
            digest: ShakeDigest::new(BIT_LENGTH),
            output_started: false,
        })
    }
}

struct Shake256 {
    digest: ShakeDigest,
    output_started: bool,
}

impl Xof for Shake256 {
    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        if self.output_started {
            return Err(AlgoError::new(ErrorKind::XofOutputStarted));
        }
        self.digest.update(input);
        Ok(())
    }

    fn output(&mut self, output: &mut [u8]) -> Result<(), AlgoError> {
        self.digest.output(output);
        self.output_started = true;
        Ok(())
    }

    fn finalize(&mut self, len: usize) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; len];
        self.digest.output_final(&mut output);
        self.output_started = false;
        Ok(output)
    }

    fn reset(&mut self) {
        self.digest.reset();
        self.output_started = false;
    }
}

#[cfg(test)]
mod tests {
    use core::any::Any;

    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params, Xof};

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
        xof.update(b"a").unwrap();
        xof.update(b"bc").unwrap();

        let mut first = [0; 20];
        let mut second = [0; 12];
        xof.output(&mut first).unwrap();
        xof.output(&mut second).unwrap();
        let rest = xof.finalize(32).unwrap();

        let output = [&first[..], &second[..], &rest[..]].concat();
        assert_eq!(hex(&output), ABC);
    }

    #[test]
    fn update_is_refused_once_output_has_begun() {
        let mut xof = xof();
        xof.update(b"abc").unwrap();
        xof.output(&mut [0; 1]).unwrap();

        let error = xof.update(b"more").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::XofOutputStarted);
    }

    #[test]
    fn finalize_and_reset_start_the_next_message() {
        let mut xof = xof();
        xof.update(b"abc").unwrap();
        xof.output(&mut [0; 1]).unwrap();
        xof.finalize(1).unwrap();

        xof.update(b"abc").unwrap();
        assert_eq!(hex(&xof.finalize(64).unwrap()), ABC);

        xof.update(b"other").unwrap();
        xof.output(&mut [0; 1]).unwrap();
        xof.reset();
        xof.update(b"abc").unwrap();
        assert_eq!(hex(&xof.finalize(64).unwrap()), ABC);
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
