use tc_kdf::KdfInit;
use tc_pbe::{PbeError, PbeGenerator, PbeGeneratorInit, PbeParamsOwned, Pkcs5S2};

use crate::digest::RowDigest;
use crate::kdf::Kdf;
use crate::{AlgoError, ErrorKind, Params};

// PBKDF2 of tc_pbe as a KDF: its params are a PbeParamsOwned of the encoded password, the salt and
// the iteration count, and each call of generate_bytes derives from the start, as Bouncy Castle's
// Pkcs5S2ParametersGenerator does, so the output comes in one piece
pub(super) struct Pbkdf2(Pkcs5S2<RowDigest>);

impl Pbkdf2 {
    pub(super) fn boxed(digest: RowDigest) -> Box<dyn Kdf> {
        Box::new(Self(Pkcs5S2::new(digest)))
    }
}

impl tc_kdf::Kdf for Pbkdf2 {
    type Error = AlgoError;

    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.derive_key(output).map_err(|error| {
            let kind = match error {
                PbeError::NotInitialised => ErrorKind::NotInitialized,
                PbeError::OutputTooLong => ErrorKind::DataLength,
                _ => ErrorKind::InvalidParams,
            };
            AlgoError::with_source(kind, error)
        })?;
        Ok(output.len())
    }
}

impl KdfInit<dyn Params> for Pbkdf2 {
    type Error = AlgoError;

    // An iteration count of 0 is InvalidParams, as are params of another type
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<PbeParamsOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(params)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

impl Kdf for Pbkdf2 {}

#[cfg(all(test, feature = "sha"))]
mod tests {
    use crate::params::{KeyLength, PbeParamsOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn derive(name: &str, iterations: usize, length: usize) -> Vec<u8> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name(name).unwrap();
        kdf.init(&PbeParamsOwned::new(
            b"password".to_vec(),
            b"salt".to_vec(),
            iterations,
        ))
        .unwrap();
        let mut output = vec![0; length];
        kdf.generate_bytes(&mut output).unwrap();
        output
    }

    #[test]
    fn the_rows_give_the_vectors_of_rfc_6070_and_rfc_7914() {
        // RFC 6070, PBKDF2-HMAC-SHA1
        assert_eq!(
            derive("PBKDF2-HMAC-SHA1", 1, 20),
            hex("0c60c80f961f0e71f3a9b524af6012062fe037a6")
        );
        assert_eq!(
            derive("PBKDF2-HMAC-SHA1", 4096, 20),
            hex("4b007901b765489abead49d926f721d065a429c1")
        );
        // The SHA-256 counterpart of the RFC 6070 case of 4096 iterations
        assert_eq!(
            derive("pbkdf2-hmac-sha-256", 4096, 32),
            hex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        );
    }

    #[test]
    fn a_count_of_0_or_other_params_are_invalid_and_generating_needs_an_init() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name("PBKDF2-HMAC-SHA256").unwrap();
        let error = kdf.generate_bytes(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = kdf
            .init(&PbeParamsOwned::new(b"p".to_vec(), b"s".to_vec(), 0))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = kdf.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
