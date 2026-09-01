//! CBC initialization parameter contract.

use tc_cipher::BlockCipherInit;
use tc_params::IvParams;

/// Parameters accepted by CBC over the underlying block cipher `C`.
///
/// Callers can implement this trait on their own parameter type. CBC consumes
/// the [`IvParams`] portion and forwards [`cipher_params`](Self::cipher_params)
/// to the underlying cipher.
pub trait CbcParams<C>: IvParams
where
    C: BlockCipherInit,
{
    /// Returns the parameters accepted by the underlying block cipher.
    fn cipher_params(&self) -> &C::Params<'_>;
}
