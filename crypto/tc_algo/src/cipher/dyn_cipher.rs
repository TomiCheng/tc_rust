use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit};

use crate::AlgoError;
use crate::params::AnyParams;

// For type erasure: every cipher in the table takes AnyParams and reports AlgoError, and is Send
// so AnyCipher can move between threads
pub(super) trait DynCipher:
    BufferedCipher<Error = AlgoError> + BufferedCipherInit<AnyParams, Error = AlgoError> + Send
{
}
