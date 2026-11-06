use tc_asn1::Asn1Oid;
use tc_macs::{Hmac, Mac as _, MacError, MacInit as _};
use tc_sha::Sha256Digest;

use crate::mac::{Mac, MacEntry};
use crate::params::KeyOwned;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of HMAC-SHA256, to give to DefaultAlgoBuilder::reg_mac. Its names and OID are those of
// Bouncy Castle's MacUtilities
pub(super) fn hmac_sha256(_context: &DefaultAlgoContext) -> Vec<Box<dyn MacEntry>> {
    vec![Box::new(HmacSha256Entry {
        aliases: [
            "HMAC/SHA256",
            "HMACSHA256",
            "HMAC-SHA-256",
            "HMAC/SHA-256",
            "HMACSHA-256",
        ]
        .map(String::from)
        .to_vec(),
        oids: vec![
            "1.2.840.113549.2.9"
                .parse()
                .expect("id-hmacWithSHA256 is a valid OID"),
        ],
    })]
}

struct HmacSha256Entry {
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
}

impl EntryBase for HmacSha256Entry {
    fn name(&self) -> &str {
        "HMAC-SHA256"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl MacEntry for HmacSha256Entry {
    fn create(&self) -> Box<dyn Mac> {
        Box::new(HmacSha256(Hmac::new(Sha256Digest::new())))
    }
}

struct HmacSha256(Hmac<Sha256Digest>);

impl Mac for HmacSha256 {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<KeyOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        // HMAC takes a key of any length
        let Ok(()) = self.0.init(key);
        Ok(())
    }

    fn mac_size(&self) -> usize {
        self.0.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.0.update(input).map_err(algo_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(algo_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

fn algo_error(error: MacError) -> AlgoError {
    let kind = match error {
        MacError::NotInitialised => ErrorKind::NotInitialized,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use core::any::Any;

    use crate::mac::Mac;
    use crate::params::KeyOwned;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    // Test case 2 of RFC 4231
    const KEY: &[u8] = b"Jefe";
    const MESSAGE: &[u8] = b"what do ya want for nothing?";
    const TAG: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn key() -> KeyOwned {
        KeyOwned::new(KEY.to_vec())
    }

    fn keyed() -> Box<dyn Mac> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut mac = algo.mac().get_by_name("HMAC-SHA256").unwrap();
        mac.init(&key()).unwrap();
        mac
    }

    #[test]
    fn the_helpers_give_the_standard_tag_by_name_alias_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        let macs = algo.mac();

        for name in ["HMAC-SHA256", "hmacsha256", "HMAC/SHA-256"] {
            let tag = macs.calculate_by_name(name, &key(), MESSAGE).unwrap();
            assert_eq!(hex(&tag), TAG);
        }

        let oid = "1.2.840.113549.2.9".parse().unwrap();
        let tag = macs.calculate_by_oid(&oid, &key(), MESSAGE).unwrap();
        assert_eq!(hex(&tag), TAG);
    }

    // Test case 1 of RFC 4231
    #[test]
    fn a_key_of_another_length_gives_its_standard_tag() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = KeyOwned::new(vec![0x0b; 20]);

        let tag = algo
            .mac()
            .calculate_by_name("HMAC-SHA256", &params, b"Hi There")
            .unwrap();
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn a_message_can_come_in_pieces() {
        let mut mac = keyed();
        assert_eq!(mac.mac_size(), 32);
        mac.update(&MESSAGE[..5]).unwrap();
        mac.update(&MESSAGE[5..]).unwrap();
        assert_eq!(hex(&mac.finalize().unwrap()), TAG);
    }

    #[test]
    fn finalize_starts_the_next_message_and_reset_discards_the_message() {
        let mut mac = keyed();
        mac.update(MESSAGE).unwrap();
        assert_eq!(hex(&mac.finalize().unwrap()), TAG);

        mac.update(b"other").unwrap();
        mac.reset();
        mac.update(MESSAGE).unwrap();
        assert_eq!(hex(&mac.finalize().unwrap()), TAG);
    }

    #[test]
    fn verify_tells_the_right_tag_from_a_wrong_one() {
        let mut mac = keyed();
        mac.update(MESSAGE).unwrap();
        let mut tag = mac.finalize().unwrap();

        mac.update(MESSAGE).unwrap();
        assert!(mac.verify(&tag).unwrap());

        tag[0] ^= 1;
        mac.update(MESSAGE).unwrap();
        assert!(!mac.verify(&tag).unwrap());
    }

    #[test]
    fn the_verify_helper_tells_the_standard_tag_from_a_wrong_one() {
        let algo = DefaultAlgoBuilder::default().build();
        let macs = algo.mac();
        let mut tag = macs
            .calculate_by_name("HMAC-SHA256", &key(), MESSAGE)
            .unwrap();
        assert_eq!(hex(&tag), TAG);

        assert!(
            macs.verify_by_name("HMAC-SHA256", &key(), MESSAGE, &tag)
                .unwrap()
        );

        tag[0] ^= 1;
        assert!(
            !macs
                .verify_by_name("HMAC-SHA256", &key(), MESSAGE, &tag)
                .unwrap()
        );
    }

    #[test]
    fn do_final_writes_the_tag_into_the_output_and_starts_the_next_message() {
        let mut mac = keyed();
        mac.update(MESSAGE).unwrap();
        let mut output = [0; 32];
        assert_eq!(mac.do_final(&mut output).unwrap(), 32);
        assert_eq!(hex(&output), TAG);

        mac.update(MESSAGE).unwrap();
        assert_eq!(hex(&mac.finalize().unwrap()), TAG);
    }

    #[test]
    fn an_output_too_short_is_data_length_and_keeps_the_message() {
        let mut mac = keyed();
        mac.update(MESSAGE).unwrap();
        let error = mac.do_final(&mut [0; 31]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
        assert_eq!(hex(&mac.finalize().unwrap()), TAG);
    }

    #[test]
    fn update_byte_gives_the_same_tag_as_update() {
        let mut mac = keyed();
        for byte in MESSAGE {
            mac.update_byte(*byte).unwrap();
        }
        assert_eq!(hex(&mac.finalize().unwrap()), TAG);
    }

    #[test]
    fn update_and_finalize_report_a_mac_that_was_not_initialized() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut mac = algo.mac().get_by_name("HMAC-SHA256").unwrap();

        let error = mac.update(MESSAGE).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = mac.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
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
        let mut mac = algo.mac().get_by_name("HMAC-SHA256").unwrap();

        let error = mac.init(&OtherParams).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
