use std::mem;

use tc_asn1::Asn1Oid;
use tc_block_modes::KeyWithIvOwned;
use tc_pbe::{PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs12, pkcs12_password_to_bytes};
use tc_sha::Sha256Digest;
use tc_zeroize::Zeroizing;

use crate::pbe::{Pbe, PbeEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

const IV_BYTES: usize = 16;

// The rows of AES in CBC mode from a password, to give to DefaultAlgoBuilder::reg_pbe. Their names,
// OIDs and PKCS#12 generator over SHA-256 are those of Bouncy Castle's PbeUtilities
pub(super) fn aes(_context: &DefaultAlgoContext) -> Vec<Box<dyn PbeEntry>> {
    vec![
        row(
            "PBEwithSHA-256and128bitAES-CBC-BC",
            ["PBEWITHSHA256AND128BITAES-CBC-BC"],
            "1.3.6.1.4.1.22554.1.2.1.2.1.2",
            16,
        ),
        row(
            "PBEwithSHA-256and192bitAES-CBC-BC",
            ["PBEWITHSHA256AND192BITAES-CBC-BC"],
            "1.3.6.1.4.1.22554.1.2.1.2.1.22",
            24,
        ),
        row(
            "PBEwithSHA-256and256bitAES-CBC-BC",
            ["PBEWITHSHA256AND256BITAES-CBC-BC"],
            "1.3.6.1.4.1.22554.1.2.1.2.1.42",
            32,
        ),
    ]
}

fn row(
    name: &'static str,
    aliases: [&str; 1],
    dotted: &str,
    key_bytes: usize,
) -> Box<dyn PbeEntry> {
    Box::new(Row {
        name,
        aliases: aliases.map(String::from).to_vec(),
        oids: vec![dotted.parse().expect("a valid OID")],
        key_bytes,
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    key_bytes: usize,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl PbeEntry for Row {
    fn create(&self) -> Box<dyn Pbe> {
        Box::new(Pkcs12Aes {
            key_bytes: self.key_bytes,
        })
    }
}

struct Pkcs12Aes {
    key_bytes: usize,
}

impl Pbe for Pkcs12Aes {
    fn target(&self) -> &str {
        "AES/CBC/PKCS7PADDING"
    }

    fn generate_params(
        &self,
        password: &str,
        salt: &[u8],
        iterations: usize,
    ) -> Result<Box<dyn Params>, AlgoError> {
        let invalid = |error| AlgoError::with_source(ErrorKind::InvalidParams, error);
        let password = pkcs12_password_to_bytes(password, false);
        let mut generator = Pkcs12::new(Sha256Digest::new());
        generator
            .init(&PbeParamsRef::new(&password, salt, iterations))
            .map_err(invalid)?;

        let mut key = Zeroizing::new(vec![0; self.key_bytes]);
        let mut iv = vec![0; IV_BYTES];
        generator
            .derive_key_and_iv(&mut key, &mut iv)
            .map_err(invalid)?;
        Ok(Box::new(KeyWithIvOwned::new(mem::take(&mut *key), iv)))
    }
}

#[cfg(test)]
mod tests {
    use crate::params::{IvParams, KeyParams, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    const SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const ITERATIONS: usize = 2048;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    // RFC 7292 has no vectors for SHA-256, so these come from its appendix B written out in Python
    const IV: &str = "30938f79be0bc0f698680e658c91b5ee";
    const ROWS: [(&str, &str, &str); 3] = [
        (
            "PBEwithSHA-256and128bitAES-CBC-BC",
            "1.3.6.1.4.1.22554.1.2.1.2.1.2",
            "d8fb52dd9042c1031f9a18e5957a3be6",
        ),
        (
            "PBEwithSHA-256and192bitAES-CBC-BC",
            "1.3.6.1.4.1.22554.1.2.1.2.1.22",
            "d8fb52dd9042c1031f9a18e5957a3be69ead00cf867836e8",
        ),
        (
            "PBEwithSHA-256and256bitAES-CBC-BC",
            "1.3.6.1.4.1.22554.1.2.1.2.1.42",
            "d8fb52dd9042c1031f9a18e5957a3be69ead00cf867836e84f3363150bd5657a",
        ),
    ];

    #[test]
    fn each_row_derives_the_expected_key_and_iv_by_name_and_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        for (name, dotted, key) in ROWS {
            let by_oid = algo.pbe().get_by_oid(&dotted.parse().unwrap()).unwrap();
            for pbe in [algo.pbe().get_by_name(name).unwrap(), by_oid] {
                let params = pbe.generate_params("password", &SALT, ITERATIONS).unwrap();
                let params = params.as_any().downcast_ref::<KeyWithIvOwned>().unwrap();
                assert_eq!(params.key(), hex(key), "{name}");
                assert_eq!(params.iv(), hex(IV), "{name}");
            }
        }
    }

    #[test]
    fn the_aliases_find_the_rows_whatever_the_case() {
        let algo = DefaultAlgoBuilder::default().build();
        for name in [
            "PBEWITHSHA256AND128BITAES-CBC-BC",
            "PBEWithSHA256And192BitAES-CBC-BC",
            "pbewithsha-256and256bitaes-cbc-bc",
        ] {
            assert!(algo.pbe().get_by_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn the_params_go_to_the_cipher_named_by_target() {
        let algo = DefaultAlgoBuilder::default().build();
        let message = b"attack at dawn";
        let pbe = algo.pbe().get_by_name(ROWS[2].0).unwrap();
        let params = pbe.generate_params("password", &SALT, ITERATIONS).unwrap();

        let sealed = algo
            .cipher()
            .encrypt_by_name(pbe.target(), params.as_ref(), message)
            .unwrap();
        assert_ne!(sealed, message);

        let params = pbe.generate_params("password", &SALT, ITERATIONS).unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name(pbe.target(), params.as_ref(), &sealed)
            .unwrap();
        assert_eq!(opened, message);
    }

    #[test]
    fn another_password_or_salt_derives_another_key() {
        let algo = DefaultAlgoBuilder::default().build();
        let pbe = algo.pbe().get_by_name(ROWS[0].0).unwrap();
        let key = |password: &str, salt: &[u8]| {
            let params = pbe.generate_params(password, salt, ITERATIONS).unwrap();
            let params = params.as_any().downcast_ref::<KeyWithIvOwned>().unwrap();
            params.key().to_vec()
        };

        let first = key("password", &SALT);
        assert_ne!(first, key("other", &SALT));
        assert_ne!(first, key("password", &[9; 8]));
    }

    #[test]
    fn an_iteration_count_of_zero_is_invalid_params() {
        let algo = DefaultAlgoBuilder::default().build();
        let pbe = algo.pbe().get_by_name(ROWS[0].0).unwrap();
        let error = pbe.generate_params("password", &SALT, 0).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
