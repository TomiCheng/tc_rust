use std::sync::Arc;

use tc_asn1::Asn1Oid;
use tc_macs::{Hmac, MacError};

use crate::digest::{DigestEntry, RowDigest};
use crate::mac::{Mac, MacEntry};
use crate::params::key::KeyOwned;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The rows of HMAC, to give to DefaultAlgoBuilder::reg_mac: one over each digest row that is on, as
// Bouncy Castle's MacUtilities makes HMAC over any digest of DigestUtilities by its name, HMAC-SHA256
// or HMAC/SHA256. NONE is no digest, and Haraka takes inputs of one length alone, so neither has one,
// and neither has a digest whose block is shorter than 16 bytes or than its digest
pub(super) fn hmac(context: &DefaultAlgoContext) -> Vec<Box<dyn MacEntry>> {
    crate::digest::BUILT_IN
        .iter()
        .flat_map(|create| create(context))
        .filter(|digest| !matches!(digest.name(), "NONE" | "HARAKA-256" | "HARAKA-512"))
        // tc_macs's Hmac takes a digest of a block of 16 bytes or more, and no longer than its digest,
        // which the sponges of a small rate, Ascon, ISAP and PHOTON-Beetle among them, are not
        .filter(|digest| {
            let digest = digest.create();
            digest.byte_length() >= 16 && digest.digest_size() <= digest.byte_length()
        })
        .map(|digest| Box::new(Row::new(Arc::from(digest))) as Box<dyn MacEntry>)
        .collect()
}

// The OIDs of Bouncy Castle's MacUtilities, by the canonical name of the row
const OIDS: &[(&str, &[&str])] = &[
    ("HMAC-MD5", &["1.3.6.1.5.5.8.1.1"]),
    ("HMAC-SHA1", &["1.3.6.1.5.5.8.1.2", "1.2.840.113549.2.7"]),
    ("HMAC-TIGER", &["1.3.6.1.5.5.8.1.3"]),
    ("HMAC-RIPEMD160", &["1.3.6.1.5.5.8.1.4"]),
    ("HMAC-SHA224", &["1.2.840.113549.2.8"]),
    ("HMAC-SHA256", &["1.2.840.113549.2.9"]),
    ("HMAC-SHA384", &["1.2.840.113549.2.10"]),
    ("HMAC-SHA512", &["1.2.840.113549.2.11"]),
    ("HMAC-SHA512-224", &["1.2.840.113549.2.12"]),
    ("HMAC-SHA512-256", &["1.2.840.113549.2.13"]),
    ("HMAC-SHA3-224", &["2.16.840.1.101.3.4.2.13"]),
    ("HMAC-SHA3-256", &["2.16.840.1.101.3.4.2.14"]),
    ("HMAC-SHA3-384", &["2.16.840.1.101.3.4.2.15"]),
    ("HMAC-SHA3-512", &["2.16.840.1.101.3.4.2.16"]),
    ("HMAC-GOST3411-2012-256", &["1.2.643.7.1.1.4.1"]),
    ("HMAC-GOST3411-2012-512", &["1.2.643.7.1.1.4.2"]),
];

struct Row {
    name: String,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    digest: Arc<dyn DigestEntry>,
}

impl Row {
    // The name of Bouncy Castle's MacUtilities: HMAC- and the digest's name, without the dash of
    // SHA- and with a dash for the slash of SHA-512/256. Every name of the digest, after HMAC-,
    // HMAC/ or HMAC alone, is an alias
    fn new(digest: Arc<dyn DigestEntry>) -> Self {
        let digest_name = digest.name().replacen("SHA-", "SHA", 1).replace('/', "-");
        let name = format!("HMAC-{digest_name}");
        let mut aliases: Vec<String> = Vec::new();
        for digest_name in
            core::iter::once(digest.name()).chain(digest.aliases().iter().map(String::as_str))
        {
            for prefix in ["HMAC-", "HMAC/", "HMAC"] {
                let alias = format!("{prefix}{digest_name}");
                if alias != name && !aliases.contains(&alias) {
                    aliases.push(alias);
                }
            }
        }
        let oids = OIDS
            .iter()
            .filter(|(row, _)| *row == name)
            .flat_map(|(_, oids)| oids.iter())
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect();
        Self {
            name,
            aliases,
            oids,
            digest,
        }
    }
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        &self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl MacEntry for Row {
    fn create(&self) -> Box<dyn Mac> {
        Box::new(HmacMac(Hmac::new(RowDigest::new(self.digest.clone()))))
    }
}

struct HmacMac(Hmac<RowDigest>);

impl tc_macs::Mac for HmacMac {
    type Error = AlgoError;

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

impl tc_macs::MacInit<dyn Params> for HmacMac {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let key = params
            .as_any()
            .downcast_ref::<KeyOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        // HMAC takes a key of any length
        let Ok(()) = tc_macs::MacInit::init(&mut self.0, key);
        Ok(())
    }
}

impl Mac for HmacMac {}

fn algo_error(error: MacError) -> AlgoError {
    let kind = match error {
        MacError::NotInitialised => ErrorKind::NotInitialized,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(all(test, feature = "sha"))]
mod tests {
    use core::any::Any;

    use crate::mac::Mac;
    use crate::params::key::KeyOwned;
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

    // RFC 2202, test case 2, over MD5 and SHA-1, by the names and OIDs of Bouncy Castle
    #[cfg(all(feature = "md", feature = "sha"))]
    #[test]
    fn hmac_over_md5_and_sha1_gives_the_tags_of_rfc_2202() {
        let algo = DefaultAlgoBuilder::default().build();
        let macs = algo.mac();
        for (name, oid, tag) in [
            (
                "HMAC-MD5",
                "1.3.6.1.5.5.8.1.1",
                "750c783e6ab0b503eaa86e310a5db738",
            ),
            (
                "HMAC-SHA1",
                "1.2.840.113549.2.7",
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
        ] {
            assert_eq!(
                hex(&macs.calculate_by_name(name, &key(), MESSAGE).unwrap()),
                tag
            );
            let oid = oid.parse().unwrap();
            assert_eq!(
                hex(&macs.calculate_by_oid(&oid, &key(), MESSAGE).unwrap()),
                tag
            );
        }
        assert!(macs.get_by_name("HMAC/SHA-1").is_ok());
        assert!(macs.get_by_name("HMACMD5").is_ok());
    }

    // Each HMAC row gives a tag of the size of its digest, and there is none over NONE or Haraka
    #[test]
    fn every_hmac_row_gives_a_tag_of_its_digest_size() {
        let algo = DefaultAlgoBuilder::default().build();
        let names: Vec<String> = algo
            .mac()
            .algorithms()
            .map(|entry| entry.name().to_string())
            .filter(|name| name.starts_with("HMAC-"))
            .collect();
        for name in &names {
            let digest = algo.digest().get_by_name(&name[5..]).unwrap_or_else(|_| {
                let digest_name = name[5..].replacen("SHA", "SHA-", 1);
                algo.digest().get_by_name(&digest_name).unwrap()
            });
            let tag = algo.mac().calculate_by_name(name, &key(), MESSAGE).unwrap();
            assert_eq!(tag.len(), digest.digest_size(), "{name}");
        }
        assert!(algo.mac().get_by_name("HMAC-NONE").is_err());
    }
}
