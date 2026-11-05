use tc_asn1::{Asn1OctetString, Asn1SequenceOf, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_zeroize::Zeroize;

use crate::{AlgoError, ErrorKind, Params};

// as_bytes gives the DER of SEQUENCE { key OCTET STRING, iv OCTET STRING OPTIONAL }
#[derive(Default)]
pub struct BlockCipherParams {
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
    der: Vec<u8>,
}

impl BlockCipherParams {
    pub fn new() -> Self {
        Self::default()
    }

    // Takes what as_bytes gives; anything else, or anything after it, is InvalidParams
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AlgoError> {
        let (read, mut sequence) =
            Asn1SequenceOf::<Asn1OctetString>::decode_der(bytes, &DecodingOptions::default())
                .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;

        let fields = match sequence.elements() {
            [key] => Some((key, None)),
            [key, iv] => Some((key, Some(iv))),
            _ => None,
        };
        let params = fields
            .filter(|_| read == bytes.len())
            .map(|(key, iv)| Self {
                key: key.as_bytes().to_vec(),
                iv: iv.map(|iv| iv.as_bytes().to_vec()),
                der: bytes.to_vec(),
            });
        sequence.zeroize();

        params.ok_or(AlgoError::new(ErrorKind::InvalidParams))
    }

    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.key.zeroize();
        self.key = key.to_vec();
        self.encode();
        self
    }

    pub fn with_iv(mut self, iv: &[u8]) -> Self {
        self.iv.zeroize();
        self.iv = Some(iv.to_vec());
        self.encode();
        self
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn iv(&self) -> Option<&[u8]> {
        self.iv.as_deref()
    }

    fn encode(&mut self) {
        let mut fields = vec![Asn1OctetString::new(&self.key)];
        if let Some(iv) = &self.iv {
            fields.push(Asn1OctetString::new(iv));
        }
        let mut sequence = Asn1SequenceOf::new(fields);
        let der = sequence.encode_to_vec(&EncodingOptions::DER);
        sequence.zeroize();

        self.der.zeroize();
        self.der = der.expect("the buffer is sized by encoded_len");
    }
}

impl Drop for BlockCipherParams {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        self.der.zeroize();
    }
}

impl Params for BlockCipherParams {
    fn as_bytes(&self) -> &[u8] {
        &self.der
    }
}

#[cfg(test)]
mod tests {
    use super::BlockCipherParams;
    use crate::{ErrorKind, Params};

    const KEY: [u8; 16] = [0x11; 16];
    const IV: [u8; 16] = [0x22; 16];

    fn der_with_iv() -> Vec<u8> {
        [&[0x30, 0x24, 0x04, 0x10][..], &KEY, &[0x04, 0x10], &IV].concat()
    }

    fn der_without_iv() -> Vec<u8> {
        [&[0x30, 0x12, 0x04, 0x10][..], &KEY].concat()
    }

    fn is_refused(bytes: &[u8]) -> bool {
        matches!(
            BlockCipherParams::from_bytes(bytes),
            Err(error) if error.kind() == ErrorKind::InvalidParams
        )
    }

    #[test]
    fn as_bytes_gives_the_key_and_the_iv_as_a_der_sequence() {
        let params = BlockCipherParams::new().with_key(&KEY).with_iv(&IV);
        assert_eq!(params.as_bytes(), der_with_iv());
    }

    #[test]
    fn as_bytes_leaves_out_an_iv_that_was_not_given() {
        let params = BlockCipherParams::new().with_key(&KEY);
        assert_eq!(params.as_bytes(), der_without_iv());
    }

    #[test]
    fn as_bytes_does_not_depend_on_which_field_was_given_first() {
        let params = BlockCipherParams::new().with_iv(&IV).with_key(&KEY);
        assert_eq!(params.as_bytes(), der_with_iv());
    }

    #[test]
    fn a_later_with_key_or_with_iv_replaces_the_earlier_value() {
        let params = BlockCipherParams::new()
            .with_key(&[0x33; 16])
            .with_iv(&[0x44; 16])
            .with_key(&KEY)
            .with_iv(&IV);
        assert_eq!(params.as_bytes(), der_with_iv());
    }

    #[test]
    fn from_bytes_takes_back_what_as_bytes_gave_with_an_iv() {
        let given = BlockCipherParams::new().with_key(&KEY).with_iv(&IV);
        let params = BlockCipherParams::from_bytes(given.as_bytes()).unwrap();

        assert_eq!(params.key, KEY);
        assert_eq!(params.iv.as_deref(), Some(&IV[..]));
        assert_eq!(params.as_bytes(), given.as_bytes());
    }

    #[test]
    fn from_bytes_takes_back_what_as_bytes_gave_without_an_iv() {
        let given = BlockCipherParams::new().with_key(&KEY);
        let params = BlockCipherParams::from_bytes(given.as_bytes()).unwrap();

        assert_eq!(params.key, KEY);
        assert_eq!(params.iv, None);
        assert_eq!(params.as_bytes(), given.as_bytes());
    }

    #[test]
    fn from_bytes_refuses_anything_after_the_sequence() {
        let mut bytes = der_with_iv();
        bytes.push(0);
        assert!(is_refused(&bytes));
    }

    #[test]
    fn from_bytes_refuses_a_sequence_with_no_fields_or_too_many() {
        assert!(is_refused(&[0x30, 0x00]));
        assert!(is_refused(&[
            0x30, 0x06, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00
        ]));
    }

    #[test]
    fn from_bytes_refuses_ber_that_is_not_der() {
        let long_form_length = [&[0x30, 0x81, 0x12, 0x04, 0x10][..], &KEY].concat();
        assert!(is_refused(&long_form_length));
    }

    #[test]
    fn from_bytes_refuses_what_is_not_a_sequence_of_octet_strings() {
        assert!(is_refused(&[]));
        assert!(is_refused(&[0x04, 0x01, 0x00]));
        assert!(is_refused(&[0x30, 0x03, 0x02, 0x01, 0x05]));

        let set = [&[0x31, 0x12, 0x04, 0x10][..], &KEY].concat();
        assert!(is_refused(&set));
    }
}
