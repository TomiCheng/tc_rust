use rand::CryptoRng;
use tc_block_cipher::KeyParams;

use super::AnyParams;
use crate::cipher::{Algorithm, Mode};

pub(super) type Generate = fn(&AnyParams, usize, &mut dyn CryptoRng) -> AnyParams;

struct ModeSpec {
    mode: Mode,
    generate: Generate,
}

struct StandaloneSpec {
    algorithm: Algorithm,
    generate: Generate,
}

const MODES: &[ModeSpec] = &[
    ModeSpec {
        mode: Mode::Ecb,
        generate: |key, _, _| key.clone(),
    },
    ModeSpec {
        mode: Mode::Cbc,
        generate: |key, block_size, rng| iv(key, block_size, rng),
    },
    ModeSpec {
        mode: Mode::Cfb,
        generate: |key, block_size, rng| iv(key, block_size, rng),
    },
    ModeSpec {
        mode: Mode::Ofb,
        generate: |key, block_size, rng| iv(key, block_size, rng),
    },
    ModeSpec {
        mode: Mode::Ctr,
        generate: |key, block_size, rng| iv(key, block_size, rng),
    },
    ModeSpec {
        mode: Mode::Ccm,
        generate: |key, _, rng| aead(key, 12, 128, rng),
    },
    ModeSpec {
        mode: Mode::Eax,
        generate: |key, block_size, rng| aead(key, block_size, block_size * 4, rng),
    },
    ModeSpec {
        mode: Mode::Gcm,
        generate: |key, _, rng| aead(key, 12, 128, rng),
    },
    ModeSpec {
        mode: Mode::Ocb,
        generate: |key, _, rng| aead(key, 12, 128, rng),
    },
];

const STANDALONE: &[StandaloneSpec] = &[
    #[cfg(feature = "chacha")]
    StandaloneSpec {
        algorithm: Algorithm::ChaCha,
        generate: |key, _, rng| iv(key, 8, rng),
    },
    #[cfg(feature = "chacha")]
    StandaloneSpec {
        algorithm: Algorithm::ChaCha7539,
        generate: |key, _, rng| iv(key, 12, rng),
    },
    #[cfg(feature = "chacha")]
    StandaloneSpec {
        algorithm: Algorithm::XChaCha20,
        generate: |key, _, rng| iv(key, 24, rng),
    },
    #[cfg(feature = "ascon")]
    StandaloneSpec {
        algorithm: Algorithm::AsconAead128,
        generate: |key, _, rng| aead(key, 16, 128, rng),
    },
    #[cfg(feature = "ascon")]
    StandaloneSpec {
        algorithm: Algorithm::Ascon128,
        generate: |key, _, rng| aead(key, 16, 128, rng),
    },
    #[cfg(feature = "ascon")]
    StandaloneSpec {
        algorithm: Algorithm::Ascon128a,
        generate: |key, _, rng| aead(key, 16, 128, rng),
    },
    #[cfg(feature = "ascon")]
    StandaloneSpec {
        algorithm: Algorithm::Ascon80pq,
        generate: |key, _, rng| aead(key, 16, 128, rng),
    },
];

pub(super) fn for_mode(mode: Mode) -> Option<Generate> {
    MODES
        .iter()
        .find(|spec| spec.mode == mode)
        .map(|spec| spec.generate)
}

pub(super) fn for_algorithm(algorithm: Algorithm) -> Option<Generate> {
    STANDALONE
        .iter()
        .find(|spec| spec.algorithm == algorithm)
        .map(|spec| spec.generate)
}

fn random(len: usize, rng: &mut dyn CryptoRng) -> Vec<u8> {
    let mut bytes = vec![0; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn iv(key: &AnyParams, len: usize, rng: &mut dyn CryptoRng) -> AnyParams {
    key.clone().with_iv(random(len, rng))
}

fn aead(key: &AnyParams, nonce_len: usize, mac_size: usize, rng: &mut dyn CryptoRng) -> AnyParams {
    AnyParams::aead(
        KeyParams::key(key).to_vec(),
        mac_size,
        random(nonce_len, rng),
        Vec::new(),
    )
}
