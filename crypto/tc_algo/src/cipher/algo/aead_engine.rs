use core::error::Error;

use tc_aead_cipher::{AeadCipher, AeadCipherInit, AeadError, AeadParamsOwned};
use tc_asn1::Asn1Oid;

use crate::cipher::{BufferedCipher, Cipher, CipherDirection, CipherEntry};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// The row of an AEAD cipher that is an algorithm of its own, not a mode of a block cipher
pub(super) fn row(
    name: &'static str,
    oids: &[&str],
    create: fn() -> Box<dyn Cipher>,
) -> Box<dyn CipherEntry> {
    Box::new(Row {
        name,
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        create,
    })
}

struct Row {
    name: &'static str,
    oids: Vec<Asn1Oid>,
    create: fn() -> Box<dyn Cipher>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl CipherEntry for Row {
    fn create(&self) -> Box<dyn Cipher> {
        (self.create)()
    }
}

// An AEAD engine of its own, as those of tc_chacha_aead, tc_ascon_aead, tc_grain128_aead and
// tc_sparkle_aead, behind Cipher. Its params are an AeadParamsOwned. Encryption ends with the tag,
// and decryption expects it at the end of the input; as in Bouncy Castle, update may give plaintext
// before finalize has checked the tag
pub(super) struct AeadEngine<C>(pub(super) C);

impl<C> BufferedCipher for AeadEngine<C>
where
    C: AeadCipher<Error = AeadError>,
{
    type Error = AlgoError;

    // Zero, as for a stream cipher
    fn block_size(&self) -> usize {
        0
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len).map_err(aead_error)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len).map_err(aead_error)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output).map_err(aead_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(aead_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<C, I> Cipher for AeadEngine<C>
where
    C: AeadCipher<Error = AeadError> + AeadCipherInit<AeadParamsOwned, Error = I>,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<AeadParamsOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(direction.into(), params)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

fn aead_error(error: AeadError) -> AlgoError {
    let kind = match error {
        // A finished encryption takes a new init, so that no nonce is used twice
        AeadError::NotInitialized | AeadError::AlreadyFinalized => ErrorKind::NotInitialized,
        // Too short to hold the tag is told apart no more than a wrong tag
        AeadError::AuthenticationFailed | AeadError::CiphertextTooShort { .. } => {
            ErrorKind::InvalidCiphertext
        }
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

// The first known answer of an AEAD row, whose plaintext and AAD are empty: its tag alone, which
// decrypts back to nothing
#[cfg(all(
    test,
    any(
        feature = "ascon-aead",
        feature = "grain128-aead",
        feature = "sparkle-aead"
    )
))]
pub(super) fn assert_empty_vector(name: &str, key: &str, nonce: &str, tag: &str) {
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    let unhex = |hex: &str| -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    };
    let params = AeadParamsOwned::new(unhex(key), unhex(nonce), tag.len() / 2, Vec::new());
    let algo = DefaultAlgoBuilder::default().build();
    let ciphers = algo.cipher();
    let sealed = ciphers.encrypt_by_name(name, &params, &[]).unwrap();
    assert_eq!(sealed, unhex(tag), "{name}");
    let opened = ciphers.decrypt_by_name(name, &params, &sealed).unwrap();
    assert!(opened.is_empty(), "{name}");

    let mut changed = sealed.clone();
    changed[0] ^= 1;
    let error = ciphers
        .decrypt_by_name(name, &params, &changed)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidCiphertext, "{name}");
}
