use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The parameters of the ECDH KEK derivation, BC's `DHKdfParameters`.
pub trait EcdhKekParams {
    /// The key-wrap algorithm the KEK is for, BC's `AlgID`, written into
    /// `keyInfo`. It must match the sender's encoding exactly: NULL and absent
    /// parameters derive different keys.
    fn key_info(&self) -> &AlgorithmIdentifier;

    /// The KEK length in bits, BC's `KeySize`, written into `suppPubInfo`. It
    /// should match the length asked of `generate_bytes`; nothing checks that.
    fn key_size(&self) -> u32;

    /// The shared secret Z, BC's `Z`. Secret material: avoid logging it or keeping
    /// copies.
    fn z(&self) -> &[u8];

    /// The sender's user keying material, BC's `ExtraInfo`, written into
    /// `entityUInfo`. Empty when there is none, which leaves `entityUInfo` out.
    fn extra_info(&self) -> &[u8];
}
