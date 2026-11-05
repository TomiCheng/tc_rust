use tc_asn1::Asn1Oid;

pub trait EntryBase {
    // The primary key of the row: no two rows of a provider have the same name
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }
}
