use crate::Signer;

/// A signer that recovers part or all of the message from the signature, BC's
/// `ISignerWithRecovery`, as ISO 9796-2 does.
pub trait SignerWithRecovery: Signer {
    /// Whether the last verification recovered the whole message, BC's `HasFullMessage`.
    fn has_full_message(&self) -> bool;

    /// The message recovered by the last verification or by
    /// [`update_with_recovered_message`](Self::update_with_recovered_message), if any.
    fn recovered_message(&self) -> Option<&[u8]>;

    /// Recovers the message part held in `signature` and feeds it to the signer, so that
    /// later updates carry only the rest of the message; it must come before any update.
    /// Fails on a signature that does not decode.
    fn update_with_recovered_message(&mut self, signature: &[u8]) -> Result<(), Self::Error>;
}
