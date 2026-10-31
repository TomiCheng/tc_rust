use core::fmt;

use tc_asn1::NamedOid;

use super::KeyPairGenerator;

#[derive(Clone, Copy, Debug)]
pub struct KeyPairGeneratorEntry {
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
}

impl KeyPairGeneratorEntry {
    pub fn name(&self) -> &'static str {
        todo!()
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        todo!()
    }

    pub fn generator(&'static self) -> KeyPairGenerator {
        todo!()
    }
}

impl fmt::Display for KeyPairGeneratorEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
