use core::fmt;

use tc_asn1::NamedOid;

use super::KeyGenerator;

#[derive(Clone, Copy, Debug)]
pub struct KeyGeneratorEntry {
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
}

impl KeyGeneratorEntry {
    pub fn name(&self) -> &'static str {
        todo!()
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        todo!()
    }

    pub fn generator(&'static self) -> KeyGenerator {
        todo!()
    }
}

impl fmt::Display for KeyGeneratorEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
