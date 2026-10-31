// Three small tables, block ciphers, modes and paddings, expand on first use into every valid
// combination, each with a canonical name such as AES/CBC/PKCS7PADDING

#[cfg(feature = "aes")]
mod aes;
mod compose;
#[cfg(feature = "des")]
mod des;
mod modes;
mod paddings;
pub(in crate::cipher) mod specs;

use std::sync::LazyLock;

use modes::MODES;
use paddings::PADDINGS;
use specs::{AlgorithmSpec, PaddingKind};

use super::CipherEntry;

pub(super) use compose::create;

// Statics rather than consts, here and in modes and paddings: entries point into them and are
// matched by address, which a const does not keep
static ALGORITHMS: &[AlgorithmSpec] = &[
    #[cfg(feature = "aes")]
    aes::AES,
    #[cfg(feature = "des")]
    des::DES,
];

// One entry per valid combination: an AEAD mode only with NoPadding, a mode only on the block
// sizes it takes
pub(super) static CIPHERS: LazyLock<Vec<CipherEntry>> = LazyLock::new(|| {
    let mut entries = Vec::new();
    for algorithm in ALGORITHMS {
        for mode in MODES.iter().filter(|mode| mode.supports(algorithm)) {
            for padding in PADDINGS {
                if mode.aead && padding.kind != PaddingKind::NoPadding {
                    continue;
                }
                let oids = algorithm
                    .oids
                    .iter()
                    .find(|(m, p, _)| *m == mode.kind && *p == padding.kind)
                    .map_or(&[][..], |(_, _, oids)| oids);
                entries.push(CipherEntry::new(algorithm, mode, padding, oids));
            }
        }
    }
    entries
});

// Splits a name such as AES/CBC/PKCS7PADDING into its three parts, as Bouncy Castle does: ASCII
// case does not matter, '-' and '_' are the same, a missing mode is ECB, and a missing padding is
// the mode's default
pub(super) fn find(name: &str) -> Option<&'static CipherEntry> {
    let mut parts = name.split('/');
    let algorithm = parts.next()?;
    let mode = parts.next().filter(|part| !part.is_empty());
    let padding = parts.next().filter(|part| !part.is_empty());
    if parts.next().is_some() {
        return None;
    }
    let algorithm = ALGORITHMS
        .iter()
        .find(|spec| spec.names.iter().any(|known| same_name(known, algorithm)))?;
    let mode = match mode {
        Some(mode) => MODES
            .iter()
            .find(|spec| spec.names.iter().any(|known| same_name(known, mode)))?,
        None => &MODES[0],
    };
    let padding = match padding {
        Some(padding) => PADDINGS
            .iter()
            .find(|spec| spec.names.iter().any(|known| same_name(known, padding)))?,
        None => PADDINGS
            .iter()
            .find(|spec| spec.kind == mode.default_padding())?,
    };
    CIPHERS
        .iter()
        .find(|entry| entry.is(algorithm, mode, padding))
}

fn same_name(known: &str, name: &str) -> bool {
    let normalize = |byte: u8| match byte {
        b'_' => b'-',
        other => other.to_ascii_uppercase(),
    };
    known.len() == name.len()
        && known
            .bytes()
            .zip(name.bytes())
            .all(|(a, b)| normalize(a) == normalize(b))
}
