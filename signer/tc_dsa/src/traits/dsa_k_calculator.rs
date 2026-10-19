/// BC's `IDsaKCalculator`: the secret k of each signature, in [1, n − 1], as integers of
/// type `I`.
///
/// BC's two `Init`s are one here, as a random calculator takes its random source when built:
/// it reads only n, and a deterministic one, such as RFC 6979's, n, d and the message. So
/// BC's `IsDeterministic` is not needed either.
pub trait DsaKCalculator<I> {
    /// Starts the k values of one signature: by the group order `n`, the private value `d`
    /// and `message`, usually a hash.
    fn init(&mut self, n: &I, d: &I, message: &[u8]);

    /// The next k in [1, n − 1]. Panics before `init`.
    fn next_k(&mut self) -> I;
}
