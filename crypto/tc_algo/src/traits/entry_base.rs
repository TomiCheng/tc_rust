use tc_asn1::Asn1Oid;

pub trait EntryBase: Send + Sync {
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }

    // Whether `name` names the row: by default its name or one of its aliases, whatever the case. A
    // row whose names take a value, as `AES/CFB8/NOPADDING` does, says so itself
    fn matches_name(&self, name: &str) -> bool {
        self.name().eq_ignore_ascii_case(name)
            || self
                .aliases()
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
    }
}
