use tc_asn1::Asn1Oid;

/// The parameters of the DH KEK derivation, BC's `DHKdfParameters`.
pub trait DhKekParams {
    /// The key-wrap algorithm the KEK is for, BC's `Algorithm`, written into each block's
    /// `KeySpecificInfo`.
    fn algorithm(&self) -> &Asn1Oid;

    /// The KEK length in bits, BC's `KeySize`, written into `suppPubInfo`. It should match the
    /// length asked of `generate_bytes`; nothing checks that.
    fn key_size(&self) -> u32;

    /// The shared secret ZZ, BC's `Z`. Secret material: avoid logging it or keeping copies.
    fn z(&self) -> &[u8];

    /// Party A's user keying material, BC's `ExtraInfo`, written into `partyAInfo`. Empty when
    /// there is none, which leaves `partyAInfo` out; RFC 2631 makes it 512 bits when present.
    fn extra_info(&self) -> &[u8];
}
