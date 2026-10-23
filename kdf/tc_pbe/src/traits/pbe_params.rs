/// The parameters of every password-based generator, the three values of BC's
/// `PbeParametersGenerator.Init`.
pub trait PbeParams {
    /// The password, already encoded as the scheme expects, for example by
    /// `pkcs12_password_to_bytes`. Secret material: avoid logging it or keeping copies.
    fn password(&self) -> &[u8];

    /// The salt; empty when there is none.
    fn salt(&self) -> &[u8];

    /// How many times the scheme iterates. Each generator decides in `init` which counts it
    /// takes.
    fn iteration_count(&self) -> usize;
}
