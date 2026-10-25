/// The parameters of KDF1, KDF2 and the other digest-based functions, BC's `KdfParameters`:
/// the shared secret and optional context.
pub trait KdfParams {
    /// The shared secret, BC's `Z`. Secret material: avoid logging it or keeping copies.
    fn shared_secret(&self) -> &[u8];

    /// Context hashed in after the counter, BC's `IV`. Empty when there is none, which is what
    /// BC's `Iso18033KdfParameters` amounts to.
    fn iv(&self) -> &[u8];
}
