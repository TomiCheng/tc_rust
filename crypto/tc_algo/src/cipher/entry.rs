use core::fmt;

use tc_asn1::NamedOid;

use super::AnyCipher;

#[derive(Clone, Copy, Debug)]
pub struct CipherEntry {
    // The first is the canonical name, such as AES/CBC/PKCS7PADDING, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
}

impl CipherEntry {
    pub fn name(&self) -> &'static str {
        todo!()
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        todo!()
    }

    pub fn cipher(&'static self) -> AnyCipher {
        todo!()
    }
}

impl fmt::Display for CipherEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
