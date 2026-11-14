use core::fmt;

use tc_block_cipher::{BlockCipher, BlockError};

// An engine that takes only params of its own, keyed by a bare key as Bouncy Castle's engines take
// a KeyParameter, with the defaults keyed! gives it: RC2 with an effective key size of the whole
// key, RC5 with 12 rounds, GOST 28147 with its default S-box, Threefish with a tweak of zeros. Its
// own params go to the engine as they are
pub(super) struct Keyed<E>(pub(super) E);

impl<E: BlockCipher<Error = BlockError>> BlockCipher for Keyed<E> {
    type Error = BlockError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.0.process_block(input, output)
    }
}

impl<E: fmt::Display> fmt::Display for Keyed<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// `keyed!(Engine, OwnParams, |key| params of the key)`: a bare key, alone in ECB and whole with its
// IV through the other modes, which pass params with an IV on to the engine, gives the engine the
// params of the key; the engine's own params, alone in ECB and stripped of their IV by the other
// modes, go to it as they are
macro_rules! keyed {
    ($engine:ty, $own:ty, |$key:ident| $params:expr) => {
        impl tc_block_cipher::BlockCipherInit<$crate::params::KeyOwned>
            for $crate::cipher::algo::keyed::Keyed<$engine>
        {
            type Error = tc_block_cipher::InitError;

            fn init(
                &mut self,
                direction: tc_block_cipher::CipherDirection,
                params: &$crate::params::KeyOwned,
            ) -> Result<(), tc_block_cipher::InitError> {
                let $key = tc_block_cipher::KeyParams::key(params);
                tc_block_cipher::BlockCipherInit::init(&mut self.0, direction, &$params)
            }
        }

        impl tc_block_cipher::BlockCipherInit<$crate::params::KeyWithIvOwned>
            for $crate::cipher::algo::keyed::Keyed<$engine>
        {
            type Error = tc_block_cipher::InitError;

            fn init(
                &mut self,
                direction: tc_block_cipher::CipherDirection,
                params: &$crate::params::KeyWithIvOwned,
            ) -> Result<(), tc_block_cipher::InitError> {
                let $key = tc_block_cipher::KeyParams::key(params);
                tc_block_cipher::BlockCipherInit::init(&mut self.0, direction, &$params)
            }
        }

        // The params of an AEAD mode, which passes them on whole: the engine takes only the key
        impl tc_block_cipher::BlockCipherInit<tc_aead_cipher::AeadParamsOwned>
            for $crate::cipher::algo::keyed::Keyed<$engine>
        {
            type Error = tc_block_cipher::InitError;

            fn init(
                &mut self,
                direction: tc_block_cipher::CipherDirection,
                params: &tc_aead_cipher::AeadParamsOwned,
            ) -> Result<(), tc_block_cipher::InitError> {
                let $key = tc_block_cipher::KeyParams::key(params);
                tc_block_cipher::BlockCipherInit::init(&mut self.0, direction, &$params)
            }
        }

        // The engine's own params with an IV, as CTS in CBC passes them on whole
        impl<'v> tc_block_cipher::BlockCipherInit<$crate::cipher::algo::buffered::IvView<'v, $own>>
            for $crate::cipher::algo::keyed::Keyed<$engine>
        {
            type Error = tc_block_cipher::InitError;

            fn init(
                &mut self,
                direction: tc_block_cipher::CipherDirection,
                params: &$crate::cipher::algo::buffered::IvView<'v, $own>,
            ) -> Result<(), tc_block_cipher::InitError> {
                tc_block_cipher::BlockCipherInit::init(&mut self.0, direction, params.params)
            }
        }

        impl tc_block_cipher::BlockCipherInit<$own>
            for $crate::cipher::algo::keyed::Keyed<$engine>
        {
            type Error = tc_block_cipher::InitError;

            fn init(
                &mut self,
                direction: tc_block_cipher::CipherDirection,
                params: &$own,
            ) -> Result<(), tc_block_cipher::InitError> {
                tc_block_cipher::BlockCipherInit::init(&mut self.0, direction, params)
            }
        }
    };
}

pub(super) use keyed;
