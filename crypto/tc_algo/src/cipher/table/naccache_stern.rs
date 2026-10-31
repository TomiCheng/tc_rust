use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_buffered_cipher::BufferedAsymmetricBlockCipher;
use tc_naccache_stern::{NaccacheSternEngine, NaccacheSternError};

use super::specs::{AsymmetricPaddingKind, AsymmetricSpec};
use crate::cipher::dyn_cipher::{DynCipher, Mapped};
use crate::cipher::init_params::{InitParams, NaccacheSternKey};
use crate::params::{AnyKeyParams, AnyPrivateKey, AnyPublicKey};

// The engine, taking either key through NaccacheSternKey; it refuses the public key to decrypt
struct Engine(NaccacheSternEngine);

impl AsymmetricBlockCipherInit<NaccacheSternKey> for Engine {
    type Error = NaccacheSternError;

    fn init(
        &mut self,
        direction: CipherDirection,
        key: &NaccacheSternKey,
    ) -> Result<(), NaccacheSternError> {
        match key {
            NaccacheSternKey::Public(key) => self.0.init(direction, key),
            NaccacheSternKey::Private(key) => self.0.init(direction, key),
        }
    }
}

impl AsymmetricBlockCipher for Engine {
    type Error = NaccacheSternError;

    fn input_block_size(&self) -> usize {
        self.0.input_block_size()
    }

    fn output_block_size(&self) -> usize {
        self.0.output_block_size()
    }

    fn process_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, NaccacheSternError> {
        self.0.process_block(input, output)
    }
}

// Called only with NoPadding, the one padding it takes
fn create(_padding: AsymmetricPaddingKind) -> Box<dyn DynCipher> {
    let cipher = BufferedAsymmetricBlockCipher::new(Engine(NaccacheSternEngine::new()));
    Box::new(Mapped::<_, NaccacheSternKey>::new(cipher))
}

fn key(key: &AnyKeyParams) -> Option<InitParams> {
    match key {
        AnyKeyParams::Public(AnyPublicKey::NaccacheStern(key)) => Some(InitParams::NaccacheStern(
            NaccacheSternKey::Public(key.clone()),
        )),
        AnyKeyParams::Private(AnyPrivateKey::NaccacheStern(key)) => Some(
            InitParams::NaccacheStern(NaccacheSternKey::Private(key.clone())),
        ),
        _ => None,
    }
}

// No padding at all: the point of the scheme is that multiplying two ciphertexts adds their
// messages, which a padding would break. Bouncy Castle's engine is named NaccacheStern; its
// factory has no name and no OID for it
pub(super) const NACCACHE_STERN: AsymmetricSpec = AsymmetricSpec {
    names: &["NACCACHESTERN", "NACCACHE-STERN"],
    paddings: &[AsymmetricPaddingKind::NoPadding],
    create,
    key,
    oids: &[],
};
