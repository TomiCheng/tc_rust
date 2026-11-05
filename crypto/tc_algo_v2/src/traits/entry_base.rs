use tc_asn1::Asn1Oid;

pub trait EntryBase {
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }
}
