/// The parameters of HKDF, BC's `HkdfParameters`.
pub trait HkdfParams {
    /// The input keying material, or the pseudorandom key itself when
    /// [`skip_extract`](Self::skip_extract) is true. Secret material: avoid logging it or keeping
    /// copies.
    fn ikm(&self) -> &[u8];

    /// The extract step's salt. Empty when there is none, which RFC 5869 turns into `HashLen`
    /// zero bytes, as BC does.
    fn salt(&self) -> &[u8];

    /// The expand step's `info`; empty when there is none.
    fn info(&self) -> &[u8];

    /// Whether to skip the extract step and use the IKM as the pseudorandom key, as BC's
    /// `SkipExtractParameters`.
    fn skip_extract(&self) -> bool;
}
