use std::sync::OnceLock;

use tc_asn1::Asn1Oid;
use tc_buffered_cipher::CipherDirection;

use super::table::{build_table, find};
use super::{AnyCipher, CipherEntry};
use crate::params::AnyParams;
use crate::{AlgoError, ErrorKind, Policy};

/// Ciphers by name or OID, after Bouncy Castle's `CipherUtilities`, from
/// [`Algo::cipher`](crate::Algo::cipher): block, stream, AEAD, IES and asymmetric. A cipher is found
/// by its full name, such as `AES/CBC/PKCS7PADDING`, initialized with an [`AnyParams`] for one
/// direction, fed, then finished.
#[derive(Clone, Copy, Debug)]
pub struct CipherFactory<'a> {
    policy: &'a Policy,
    // The whole table, built once for the Algo on first use
    table: &'a OnceLock<Vec<CipherEntry>>,
    // Filtered from that table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<CipherEntry>>,
}

impl<'a> CipherFactory<'a> {
    pub(crate) fn new(
        policy: &'a Policy,
        table: &'a OnceLock<Vec<CipherEntry>>,
        listed: &'a OnceLock<Vec<CipherEntry>>,
    ) -> Self {
        Self {
            policy,
            table,
            listed,
        }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'a CipherEntry> {
        self.listed
            .get_or_init(|| {
                self.table()
                    .iter()
                    .filter(|entry| self.policy.lists_by(|rule| entry.matches_rule(rule)))
                    .cloned()
                    .collect()
            })
            .iter()
    }

    // The name is the full transformation, such as AES/CBC/PKCS7PADDING, matched as Bouncy Castle
    // does: without regard to ASCII case, with '-' and '_' the same, ECB for a missing mode and the
    // mode's default for a missing padding
    pub fn get_by_name(self, name: &str) -> Result<AnyCipher, AlgoError> {
        find(self.table(), name)
            .map(CipherEntry::cipher)
            .ok_or(AlgoError::new(ErrorKind::UnknownCipher))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<AnyCipher, AlgoError> {
        find_by_oid(self.table(), oid)
            .map(CipherEntry::cipher)
            .ok_or(AlgoError::new(ErrorKind::UnknownCipher))
    }

    // Finds the cipher by name, initializes it and runs the whole input through it
    pub fn encrypt(
        self,
        name: &str,
        params: &AnyParams,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        self.run(name, CipherDirection::Encrypt, params, input)
    }

    pub fn decrypt(
        self,
        name: &str,
        params: &AnyParams,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        self.run(name, CipherDirection::Decrypt, params, input)
    }

    fn run(
        self,
        name: &str,
        direction: CipherDirection,
        params: &AnyParams,
        input: &[u8],
    ) -> Result<Vec<u8>, AlgoError> {
        let mut cipher = self.get_by_name(name)?;
        cipher.init(direction, params)?;
        let mut output = cipher.update(input)?;
        output.extend(cipher.finalize()?);
        Ok(output)
    }

    fn table(self) -> &'a [CipherEntry] {
        self.table.get_or_init(build_table)
    }
}

fn find_by_oid<'a>(table: &'a [CipherEntry], oid: &Asn1Oid) -> Option<&'a CipherEntry> {
    table
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
