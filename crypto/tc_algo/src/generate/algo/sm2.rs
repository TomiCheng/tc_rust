use rand_core::CryptoRng;
use tc_asym_cipher::KeyPairGeneratorInit;
use tc_ec_key::EcKeyPairGenerator;

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry};
use crate::params::key::sm2::{Sm2Curve, sm2_key_generation_params};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The row of SM2, to give to DefaultAlgoBuilder::reg_key_pair_generator: an EC key pair on
// sm2p256v1, the curve of GM/T 0003, which the SM2 rows of the cipher factory take. Bouncy Castle
// makes it with its EC generator and the curve's domain; here the curve is fixed, so the row takes
// no params
pub(super) fn sm2(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    vec![Box::new(Row {
        rand: context.rand(),
    })]
}

struct Row {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        "SM2"
    }
}

impl KeyPairGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(Sm2 {
            rand: (self.rand)(),
        })
    }
}

// It needs no init, and init refuses any params, since the curve is the only one there is
struct Sm2 {
    rand: Box<dyn CryptoRng>,
}

impl tc_asym_cipher::KeyPairGenerator for Sm2 {
    type PublicKey = Box<dyn Params>;
    type PrivateKey = Box<dyn Params>;
    type Error = AlgoError;

    fn generate_key_pair(&mut self) -> Result<(Box<dyn Params>, Box<dyn Params>), AlgoError> {
        let mut generator = EcKeyPairGenerator::<Sm2Curve, _>::new(self.rand.as_mut());
        generator
            .init(&sm2_key_generation_params())
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        let (public, private) = tc_asym_cipher::KeyPairGenerator::generate_key_pair(&mut generator)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))?;
        Ok((Box::new(public), Box::new(private)))
    }
}

impl tc_asym_cipher::KeyPairGeneratorInit<dyn Params> for Sm2 {
    type Error = AlgoError;

    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidParams))
    }
}

impl KeyPairGenerator for Sm2 {}

#[cfg(test)]
mod tests {
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const MESSAGE: &[u8] = b"attack at dawn";

    #[test]
    fn a_generated_pair_encrypts_and_decrypts_in_either_order_of_the_ciphertext() {
        let algo = DefaultAlgoBuilder::default().build();
        let pair = algo.key_pair_generator().generate_by_name("SM2").unwrap();
        let ciphers = algo.cipher();
        let mut sealed = Vec::new();
        for name in ["SM2", "SM2//C1C2C3", "SM2//C1C3C2", "sm2/ecb/c1c3c2"] {
            let ciphertext = ciphers
                .encrypt_by_name(name, pair.public(), MESSAGE)
                .unwrap();
            // An uncompressed point of 65 bytes, the message and a hash of 32
            assert_eq!(ciphertext.len(), 65 + MESSAGE.len() + 32, "{name}");
            let opened = ciphers
                .decrypt_by_name(name, pair.private(), &ciphertext)
                .unwrap();
            assert_eq!(opened, MESSAGE, "{name}");
            sealed.push(ciphertext);
        }

        // The other order does not open it
        let error = ciphers
            .decrypt_by_name("SM2//C1C3C2", pair.private(), &sealed[0])
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);
    }

    #[test]
    fn the_cipher_refuses_a_changed_ciphertext_and_the_wrong_key_for_the_direction() {
        let algo = DefaultAlgoBuilder::default().build();
        let pair = algo.key_pair_generator().generate_by_name("SM2").unwrap();
        let ciphers = algo.cipher();
        let mut sealed = ciphers
            .encrypt_by_name("SM2", pair.public(), MESSAGE)
            .unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        let error = ciphers
            .decrypt_by_name("SM2", pair.private(), &sealed)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidCiphertext);

        let error = ciphers
            .encrypt_by_name("SM2", pair.private(), MESSAGE)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn the_generator_takes_no_params() {
        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_pair_generator();
        let pair = generators.generate_by_name("SM2").unwrap();
        let error = generators
            .generate_by_name_with("SM2", pair.public())
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
