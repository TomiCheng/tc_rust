use tc_asn1::Asn1Oid;
use tc_dh::DhBasicAgreement;
use tc_ies::{IesEngine, IesError, IesParamsRef};
use tc_kdf::kdf::Kdf2;
use tc_macs::{Hmac, Mac};
use tc_sha::Sha1Digest;
use tc_zeroize::Zeroize;

use crate::cipher::{BufferedCipher, Cipher, CipherDirection, CipherEntry};
use crate::params::IesDhParams;
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of IES, to give to DefaultAlgoBuilder::reg_cipher. Its name and parts are those of Bouncy
// Castle's CipherUtilities: DH, KDF2 and HMAC over SHA-1, and XOR with the output of the KDF
pub(super) fn ies(_context: &DefaultAlgoContext) -> Vec<Box<dyn CipherEntry>> {
    vec![Box::new(Row)]
}

struct Row;

impl EntryBase for Row {
    fn name(&self) -> &str {
        "IES"
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }
}

impl CipherEntry for Row {
    fn create(&self) -> Box<dyn Cipher> {
        let mac = Hmac::new(Sha1Digest::new());
        let mac_size = mac.mac_size();
        Box::new(Ies {
            engine: IesEngine::new(DhBasicAgreement::new(), Kdf2::new(Sha1Digest::new()), mac),
            mac_size,
            direction: None,
            buffer: Vec::new(),
        })
    }
}

// Bouncy Castle's BufferedIesCipher: the engine takes a whole message, so the input waits in a
// buffer until do_final. Its params are an IesDhParams. The output is the ciphertext, then the tag
struct Ies {
    engine: IesEngine<DhBasicAgreement, Kdf2<Sha1Digest>, Hmac<Sha1Digest>>,
    mac_size: usize,
    direction: Option<CipherDirection>,
    buffer: Vec<u8>,
}

impl Ies {
    fn direction(&self) -> Result<CipherDirection, AlgoError> {
        self.direction
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))
    }
}

impl BufferedCipher for Ies {
    type Error = AlgoError;

    // Not a block cipher, as in Bouncy Castle
    fn block_size(&self) -> usize {
        0
    }

    fn update_output_len(&self, _input_len: usize) -> Result<usize, AlgoError> {
        self.direction()?;
        Ok(0)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        let total = self.buffer.len() + input_len;
        Ok(match self.direction()? {
            CipherDirection::Encrypt => total + self.mac_size,
            CipherDirection::Decrypt => total.saturating_sub(self.mac_size),
        })
    }

    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, AlgoError> {
        self.direction()?;
        self.buffer.extend_from_slice(input);
        Ok(0)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        if output.len() < self.output_len(0)? {
            return Err(AlgoError::new(ErrorKind::DataLength));
        }
        let result = self.engine.process_block(&self.buffer);
        self.buffer.zeroize();
        let mut result = result.map_err(algo_error)?;
        let written = result.len();
        output[..written].copy_from_slice(&result);
        result.zeroize();
        Ok(written)
    }

    fn reset(&mut self) {
        self.buffer.zeroize();
    }
}

impl Cipher for Ies {
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        self.direction = None;
        self.buffer.zeroize();
        let params = params
            .as_any()
            .downcast_ref::<IesDhParams>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.engine
            .init(
                direction.into(),
                params.private_key(),
                params.public_key(),
                &IesParamsRef::new(
                    params.derivation_v(),
                    params.encoding_v(),
                    params.mac_key_bits(),
                ),
            )
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        self.direction = Some(direction);
        Ok(())
    }
}

impl Drop for Ies {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

fn algo_error(error: IesError) -> AlgoError {
    let kind = match error {
        IesError::NotInitialised => ErrorKind::NotInitialized,
        IesError::InvalidMac | IesError::InputTooShort => ErrorKind::InvalidCiphertext,
        _ => ErrorKind::InvalidParams,
    };
    AlgoError::with_source(kind, error)
}

#[cfg(test)]
mod tests {
    use tc_block_cipher::CipherDirection as BlockDirection;
    use tc_dh::DhBasicAgreement;
    use tc_ies::{IesEngine, IesParamsRef};
    use tc_kdf::kdf::Kdf2;
    use tc_macs::Hmac;
    use tc_sha::Sha1Digest;

    use crate::cipher::CipherDirection;
    use crate::generate::KeyPair;
    use crate::params::dh_groups::rfc3526_2048;
    use crate::params::{DhPrivateKey, DhPublicKey, IesDhParams, KeyLength};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const NAME: &str = "IES";
    const MESSAGE: &[u8] = b"attack at dawn";
    const DERIVATION: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    const ENCODING: &[u8] = &[8, 7, 6, 5, 4, 3, 2, 1];
    const MAC_KEY_BITS: usize = 128;

    fn pair() -> KeyPair {
        DefaultAlgoBuilder::default()
            .build()
            .key_pair_generator()
            .generate_by_name_with("DH", &rfc3526_2048())
            .unwrap()
    }

    fn private(pair: &KeyPair) -> DhPrivateKey {
        let key = pair.private().as_any().downcast_ref::<DhPrivateKey>();
        key.unwrap().clone()
    }

    fn public(pair: &KeyPair) -> DhPublicKey {
        let key = pair.public().as_any().downcast_ref::<DhPublicKey>();
        key.unwrap().clone()
    }

    fn params(own: &KeyPair, other: &KeyPair) -> IesDhParams {
        IesDhParams::new(
            private(own),
            public(other),
            DERIVATION.to_vec(),
            ENCODING.to_vec(),
            MAC_KEY_BITS,
        )
    }

    fn seal(alice: &KeyPair, bob: &KeyPair) -> Vec<u8> {
        DefaultAlgoBuilder::default()
            .build()
            .cipher()
            .encrypt_by_name(NAME, &params(alice, bob), MESSAGE)
            .unwrap()
    }

    #[test]
    fn the_other_side_takes_back_the_message_and_the_output_ends_with_the_tag() {
        let (alice, bob) = (pair(), pair());
        let sealed = seal(&alice, &bob);
        assert_eq!(sealed.len(), MESSAGE.len() + 20);

        let opened = DefaultAlgoBuilder::default()
            .build()
            .cipher()
            .decrypt_by_name(NAME, &params(&bob, &alice), &sealed)
            .unwrap();
        assert_eq!(opened, MESSAGE);
    }

    #[test]
    fn the_row_is_the_engine_over_dh_kdf2_and_hmac_with_sha1() {
        let (alice, bob) = (pair(), pair());
        let mut engine = IesEngine::new(
            DhBasicAgreement::new(),
            Kdf2::new(Sha1Digest::new()),
            Hmac::new(Sha1Digest::new()),
        );
        engine
            .init(
                BlockDirection::Encrypt,
                &private(&alice),
                &public(&bob),
                &IesParamsRef::new(DERIVATION, ENCODING, MAC_KEY_BITS),
            )
            .unwrap();
        assert_eq!(engine.process_block(MESSAGE).unwrap(), seal(&alice, &bob));
    }

    #[test]
    fn a_message_in_pieces_gives_the_same_output_and_nothing_before_finalize() {
        let (alice, bob) = (pair(), pair());
        let algo = DefaultAlgoBuilder::default().build();
        let mut cipher = algo.cipher().get_by_name(NAME).unwrap();
        cipher
            .init(CipherDirection::Encrypt, &params(&alice, &bob))
            .unwrap();
        assert!(cipher.update(&MESSAGE[..5]).unwrap().is_empty());
        assert!(cipher.update(&MESSAGE[5..]).unwrap().is_empty());
        assert_eq!(cipher.finalize().unwrap(), seal(&alice, &bob));
    }

    #[test]
    fn a_changed_ciphertext_or_too_short_a_one_is_invalid_ciphertext() {
        let (alice, bob) = (pair(), pair());
        let algo = DefaultAlgoBuilder::default().build();
        let mut sealed = seal(&alice, &bob);
        sealed[0] ^= 1;

        let error = algo
            .cipher()
            .decrypt_by_name(NAME, &params(&bob, &alice), &sealed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);

        let error = algo
            .cipher()
            .decrypt_by_name(NAME, &params(&bob, &alice), &[0; 19])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn another_key_pair_cannot_take_it_back() {
        let (alice, bob, carol) = (pair(), pair(), pair());
        let error = DefaultAlgoBuilder::default()
            .build()
            .cipher()
            .decrypt_by_name(NAME, &params(&carol, &alice), &seal(&alice, &bob))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn init_refuses_params_of_another_type_or_a_mac_key_of_a_part_of_a_byte() {
        let (alice, bob) = (pair(), pair());
        let algo = DefaultAlgoBuilder::default().build();
        let mut cipher = algo.cipher().get_by_name(NAME).unwrap();

        let error = cipher
            .init(CipherDirection::Encrypt, &KeyLength::new(1))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let params = IesDhParams::new(
            private(&alice),
            public(&bob),
            DERIVATION.to_vec(),
            ENCODING.to_vec(),
            7,
        );
        let error = cipher.init(CipherDirection::Encrypt, &params).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn the_calls_report_a_cipher_that_was_not_initialized() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut cipher = algo.cipher().get_by_name(NAME).unwrap();
        let error = cipher.update(MESSAGE).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = cipher.finalize().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
    }

    #[test]
    fn an_output_too_short_is_data_length() {
        let (alice, bob) = (pair(), pair());
        let algo = DefaultAlgoBuilder::default().build();
        let mut cipher = algo.cipher().get_by_name(NAME).unwrap();
        cipher
            .init(CipherDirection::Encrypt, &params(&alice, &bob))
            .unwrap();
        cipher.update(MESSAGE).unwrap();
        let error = cipher.do_final(&mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
        assert_eq!(cipher.finalize().unwrap(), seal(&alice, &bob));
    }

    #[test]
    fn reset_discards_the_message_so_far() {
        let (alice, bob) = (pair(), pair());
        let algo = DefaultAlgoBuilder::default().build();
        let mut cipher = algo.cipher().get_by_name(NAME).unwrap();
        cipher
            .init(CipherDirection::Encrypt, &params(&alice, &bob))
            .unwrap();
        cipher.update(b"other").unwrap();
        cipher.reset();
        cipher.update(MESSAGE).unwrap();
        assert_eq!(cipher.finalize().unwrap(), seal(&alice, &bob));
    }
}
