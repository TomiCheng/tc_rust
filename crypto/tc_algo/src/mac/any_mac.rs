use core::fmt;

use tc_constant_time::fixed_time_eq;
use tc_macs::{Mac, MacInit};

use super::dyn_mac::DynMac;
use super::{AnyMacParams, MacEntry};
use crate::AlgoError;

pub struct AnyMac {
    entry: &'static MacEntry,
    mac: Box<dyn DynMac>,
}

impl AnyMac {
    pub(super) fn new(entry: &'static MacEntry) -> Self {
        Self {
            entry,
            mac: entry.create(),
        }
    }

    pub fn entry(&self) -> &'static MacEntry {
        self.entry
    }

    // Starts from a new MAC each time, so a failed init leaves none of an earlier key behind. An
    // operation field the MAC has no use for is refused, not ignored
    pub fn init(&mut self, params: &AnyMacParams) -> Result<(), AlgoError> {
        self.mac = self.entry.create();
        self.entry.check(params)?;
        self.mac.init(params)
    }

    pub fn mac_size(&self) -> usize {
        self.mac.mac_size()
    }

    pub fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.mac.update(input)
    }

    // The tag, after which the MAC starts the next message under the same key
    pub fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut tag = vec![0; self.mac.mac_size()];
        let written = self.mac.do_final(&mut tag)?;
        tag.truncate(written);
        Ok(tag)
    }

    // Whether `tag` is the message's tag, compared in constant time, since comparing with `==`
    // stops at the first difference and tells an attacker how much of a forged tag is right. Then
    // starts the next message, as finalize does
    pub fn verify(&mut self, tag: &[u8]) -> Result<bool, AlgoError> {
        Ok(fixed_time_eq(&self.finalize()?, tag))
    }

    pub fn reset(&mut self) {
        self.mac.reset();
    }
}

// Shows the MAC's name, never its key
impl fmt::Debug for AnyMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyMac")
            .field("name", &self.entry.name())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AnyMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry.name())
    }
}

impl Mac for AnyMac {
    type Error = AlgoError;

    fn mac_size(&self) -> usize {
        self.mac.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.mac.update(input)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.mac.do_final(output)
    }

    fn reset(&mut self) {
        self.mac.reset();
    }
}

impl MacInit<AnyMacParams> for AnyMac {
    type Error = AlgoError;

    fn init(&mut self, params: &AnyMacParams) -> Result<(), Self::Error> {
        AnyMac::init(self, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use crate::need::Need;
    use crate::params::SecretKey;

    // Stands in for a real MAC until the table has rows: the tag is two copies of the XOR of the
    // key's first byte and every message byte
    #[derive(Default)]
    struct XorMac {
        key: Option<u8>,
        sum: u8,
    }

    impl DynMac for XorMac {
        fn init(&mut self, params: &AnyMacParams) -> Result<(), AlgoError> {
            let key = params
                .key()
                .key
                .first()
                .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
            self.key = Some(*key);
            self.sum = *key;
            Ok(())
        }

        fn mac_size(&self) -> usize {
            2
        }

        fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
            self.key.ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
            self.sum = input.iter().fold(self.sum, |sum, byte| sum ^ byte);
            Ok(())
        }

        fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
            let key = self.key.ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
            if output.len() < 2 {
                return Err(AlgoError::new(ErrorKind::DataLength));
            }
            output[..2].fill(self.sum);
            self.sum = key;
            Ok(2)
        }

        fn reset(&mut self) {
            if let Some(key) = self.key {
                self.sum = key;
            }
        }
    }

    fn xor_mac(iv: Need) -> AnyMac {
        let entry = MacEntry::new(vec!["XOR-MAC".to_string()], &[], iv, || {
            Box::new(XorMac::default())
        });
        Box::leak(Box::new(entry)).mac()
    }

    fn params() -> AnyMacParams {
        AnyMacParams::new(SecretKey::new(vec![0x0f; 4]))
    }

    fn kind<T>(result: Result<T, AlgoError>) -> ErrorKind {
        result.err().expect("an error").kind()
    }

    #[test]
    fn finalize_returns_the_tag_and_starts_the_next_message_under_the_same_key() {
        let mut mac = xor_mac(Need::Forbidden);
        mac.init(&params()).unwrap();
        mac.update(&[0xf0]).unwrap();
        assert_eq!(mac.finalize().unwrap(), [0xff, 0xff]);
        mac.update(&[0xf0]).unwrap();
        assert_eq!(mac.finalize().unwrap(), [0xff, 0xff]);
    }

    #[test]
    fn verify_accepts_only_the_right_tag_and_starts_the_next_message() {
        let mut mac = xor_mac(Need::Forbidden);
        mac.init(&params()).unwrap();
        mac.update(&[0xf0]).unwrap();
        assert!(mac.verify(&[0xff, 0xff]).unwrap());
        mac.update(&[0xf0]).unwrap();
        assert!(!mac.verify(&[0xff, 0xfe]).unwrap());
        mac.update(&[0xf0]).unwrap();
        assert!(!mac.verify(&[0xff]).unwrap());
        mac.update(&[0xf0]).unwrap();
        assert!(!mac.verify(&[]).unwrap());
    }

    #[test]
    fn reset_discards_the_message_and_keeps_the_key() {
        let mut mac = xor_mac(Need::Forbidden);
        mac.init(&params()).unwrap();
        mac.update(&[0x01]).unwrap();
        mac.reset();
        assert_eq!(mac.finalize().unwrap(), [0x0f, 0x0f]);
    }

    #[test]
    fn the_mac_refuses_to_run_before_a_successful_init() {
        let mut mac = xor_mac(Need::Forbidden);
        assert_eq!(kind(mac.update(b"x")), ErrorKind::NotInitialized);
        assert_eq!(kind(mac.finalize()), ErrorKind::NotInitialized);
        assert_eq!(kind(mac.verify(b"x")), ErrorKind::NotInitialized);
    }

    #[test]
    fn init_holds_the_iv_to_what_the_row_says() {
        let with_iv = params().with_iv(vec![0; 8]);

        let mut forbidden = xor_mac(Need::Forbidden);
        assert_eq!(kind(forbidden.init(&with_iv)), ErrorKind::InvalidParams);
        assert!(forbidden.init(&params()).is_ok());

        let mut required = xor_mac(Need::Required);
        assert_eq!(kind(required.init(&params())), ErrorKind::InvalidParams);
        assert!(required.init(&with_iv).is_ok());

        let mut optional = xor_mac(Need::Optional);
        assert!(optional.init(&params()).is_ok());
        assert!(optional.init(&with_iv).is_ok());
    }

    #[test]
    fn a_failed_init_never_goes_on_under_the_previous_key() {
        let mut mac = xor_mac(Need::Forbidden);
        mac.init(&params()).unwrap();
        assert!(mac.init(&params().with_iv(vec![0; 8])).is_err());
        assert_eq!(kind(mac.update(b"x")), ErrorKind::NotInitialized);
    }

    #[test]
    fn the_contract_traits_reach_the_same_mac() {
        fn tag<M>(mac: &mut M, params: &AnyMacParams) -> Vec<u8>
        where
            M: Mac<Error = AlgoError> + MacInit<AnyMacParams, Error = AlgoError>,
        {
            MacInit::init(mac, params).unwrap();
            Mac::update(mac, &[0xf0]).unwrap();
            let mut output = vec![0; Mac::mac_size(mac)];
            assert_eq!(
                kind(Mac::do_final(mac, &mut output[..1])),
                ErrorKind::DataLength
            );
            Mac::do_final(mac, &mut output).unwrap();
            Mac::reset(mac);
            output
        }
        assert_eq!(tag(&mut xor_mac(Need::Forbidden), &params()), [0xff, 0xff]);
    }

    #[test]
    fn debug_and_display_show_the_name_and_never_the_key() {
        let mut mac = xor_mac(Need::Forbidden);
        mac.init(&params()).unwrap();
        assert_eq!(mac.to_string(), "XOR-MAC");
        let debug = format!("{mac:?}");
        assert!(debug.contains("XOR-MAC"));
        assert!(!debug.contains("15"), "{debug}");
    }
}
