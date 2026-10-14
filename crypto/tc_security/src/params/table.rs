use rand::CryptoRng;
use tc_block_cipher::KeyParams;

use super::AnyParams;
use crate::cipher::Mode;

type Generate = fn(&AnyParams, usize, &mut dyn CryptoRng) -> AnyParams;

pub(super) struct ParamsSpec {
    pub(super) mode: Mode,
    pub(super) generate: Generate,
}

pub(super) const MODES: &[ParamsSpec] = &[
    ParamsSpec {
        mode: Mode::Ecb,
        generate: key_only,
    },
    ParamsSpec {
        mode: Mode::Cbc,
        generate: block_iv,
    },
    ParamsSpec {
        mode: Mode::Cfb,
        generate: block_iv,
    },
    ParamsSpec {
        mode: Mode::Ofb,
        generate: block_iv,
    },
    ParamsSpec {
        mode: Mode::Ctr,
        generate: block_iv,
    },
    ParamsSpec {
        mode: Mode::Ccm,
        generate: nonce_12,
    },
    ParamsSpec {
        mode: Mode::Eax,
        generate: eax,
    },
    ParamsSpec {
        mode: Mode::Gcm,
        generate: nonce_12,
    },
    ParamsSpec {
        mode: Mode::Ocb,
        generate: nonce_12,
    },
];

fn random(len: usize, rng: &mut dyn CryptoRng) -> Vec<u8> {
    let mut bytes = vec![0; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn key_only(key: &AnyParams, _: usize, _: &mut dyn CryptoRng) -> AnyParams {
    key.clone()
}

fn block_iv(key: &AnyParams, block_size: usize, rng: &mut dyn CryptoRng) -> AnyParams {
    key.clone().with_iv(random(block_size, rng))
}

fn nonce_12(key: &AnyParams, _: usize, rng: &mut dyn CryptoRng) -> AnyParams {
    AnyParams::aead(
        KeyParams::key(key).to_vec(),
        128,
        random(12, rng),
        Vec::new(),
    )
}

fn eax(key: &AnyParams, block_size: usize, rng: &mut dyn CryptoRng) -> AnyParams {
    AnyParams::aead(
        KeyParams::key(key).to_vec(),
        block_size * 4,
        random(block_size, rng),
        Vec::new(),
    )
}
