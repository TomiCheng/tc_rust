// Small tables, block ciphers, modes and paddings, stream ciphers, and asymmetric ciphers and
// their paddings, expand on first use into every valid combination, each with a canonical name
// such as AES/CBC/PKCS7PADDING

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "aria")]
mod aria;
#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
mod asymmetric;
#[cfg(feature = "blowfish")]
mod blowfish;
#[cfg(feature = "camellia")]
mod camellia;
#[cfg(any(feature = "cast5", feature = "cast6"))]
mod cast;
#[cfg(feature = "chacha")]
mod chacha;
mod compose;
#[cfg(feature = "des")]
mod des;
#[cfg(feature = "desede")]
mod desede;
#[cfg(feature = "elgamal")]
mod elgamal;
#[cfg(feature = "gost28147")]
mod gost28147;
#[cfg(feature = "hc")]
mod hc;
#[cfg(any(
    feature = "idea",
    feature = "noekeon",
    feature = "rijndael",
    feature = "skipjack",
    feature = "tea",
    feature = "xtea"
))]
mod misc;
mod modes;
#[cfg(feature = "naccache-stern")]
mod naccache_stern;
mod paddings;
#[cfg(any(feature = "rc2", feature = "rc5", feature = "rc5-64", feature = "rc6"))]
mod rc;
#[cfg(any(feature = "rc4", feature = "vmpc"))]
mod rc4_family;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "salsa20")]
mod salsa20;
#[cfg(feature = "seed")]
mod seed;
#[cfg(any(feature = "serpent", feature = "tnepres"))]
mod serpent;
#[cfg(feature = "sm2")]
mod sm2;
#[cfg(feature = "sm4")]
mod sm4;
pub(in crate::cipher) mod specs;
#[cfg(feature = "threefish")]
mod threefish;
#[cfg(feature = "twofish")]
mod twofish;

use core::ptr;
use std::sync::LazyLock;

#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
use asymmetric::{ASYMMETRIC_MODE_NAMES, ASYMMETRIC_PADDINGS};
use modes::MODES;
use paddings::PADDINGS;
#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
use specs::AsymmetricSpec;
#[cfg(feature = "sm2")]
use specs::MessageSpec;
use specs::{AlgorithmSpec, PaddingKind, StreamSpec};

use super::CipherEntry;
use super::entry::Kind;

pub(super) use compose::create;

// Statics rather than consts, here and in the tables they draw on: entries point into them and
// are matched by address, which a const does not keep. In the order of Bouncy Castle's names
static ALGORITHMS: &[AlgorithmSpec] = &[
    #[cfg(feature = "aes")]
    aes::AES,
    #[cfg(feature = "aria")]
    aria::ARIA,
    #[cfg(feature = "blowfish")]
    blowfish::BLOWFISH,
    #[cfg(feature = "camellia")]
    camellia::CAMELLIA,
    #[cfg(feature = "cast5")]
    cast::CAST5,
    #[cfg(feature = "cast6")]
    cast::CAST6,
    #[cfg(feature = "des")]
    des::DES,
    #[cfg(feature = "desede")]
    desede::DESEDE,
    #[cfg(feature = "gost28147")]
    gost28147::GOST28147,
    #[cfg(feature = "idea")]
    misc::IDEA,
    #[cfg(feature = "noekeon")]
    misc::NOEKEON,
    #[cfg(feature = "rc2")]
    rc::RC2,
    #[cfg(feature = "rc5")]
    rc::RC5,
    #[cfg(feature = "rc5-64")]
    rc::RC5_64,
    #[cfg(feature = "rc6")]
    rc::RC6,
    #[cfg(feature = "rijndael")]
    misc::RIJNDAEL,
    #[cfg(feature = "seed")]
    seed::SEED,
    #[cfg(feature = "serpent")]
    serpent::SERPENT,
    #[cfg(feature = "skipjack")]
    misc::SKIPJACK,
    #[cfg(feature = "sm4")]
    sm4::SM4,
    #[cfg(feature = "tea")]
    misc::TEA,
    #[cfg(feature = "threefish")]
    threefish::THREEFISH_256,
    #[cfg(feature = "threefish")]
    threefish::THREEFISH_512,
    #[cfg(feature = "threefish")]
    threefish::THREEFISH_1024,
    #[cfg(feature = "tnepres")]
    serpent::TNEPRES,
    #[cfg(feature = "twofish")]
    twofish::TWOFISH,
    #[cfg(feature = "xtea")]
    misc::XTEA,
];

// In the order of Bouncy Castle's names
static STREAMS: &[StreamSpec] = &[
    #[cfg(feature = "rc4")]
    rc4_family::ARC4,
    #[cfg(feature = "chacha")]
    chacha::CHACHA,
    #[cfg(feature = "chacha")]
    chacha::CHACHA7539,
    #[cfg(feature = "hc")]
    hc::HC128,
    #[cfg(feature = "hc")]
    hc::HC256,
    #[cfg(feature = "salsa20")]
    salsa20::SALSA20,
    #[cfg(feature = "vmpc")]
    rc4_family::VMPC,
    #[cfg(feature = "vmpc")]
    rc4_family::VMPC_KSA3,
    #[cfg(feature = "chacha")]
    chacha::XCHACHA20,
];

#[cfg(feature = "sm2")]
static MESSAGES: &[MessageSpec] = &[sm2::SM2];

#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
static ASYMMETRIC: &[AsymmetricSpec] = &[
    #[cfg(feature = "elgamal")]
    elgamal::ELGAMAL,
    #[cfg(feature = "naccache-stern")]
    naccache_stern::NACCACHE_STERN,
    #[cfg(feature = "rsa")]
    rsa::RSA,
];

// One entry per valid combination: an AEAD mode only with NoPadding, a mode only on the block
// sizes it takes, a stream cipher alone, and an asymmetric cipher with each of its paddings
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
                let kind = Kind::Block {
                    algorithm,
                    mode,
                    padding,
                };
                entries.push(CipherEntry::new(kind, oids));
            }
        }
    }
    for algorithm in STREAMS {
        entries.push(CipherEntry::new(Kind::Stream { algorithm }, algorithm.oids));
    }
    #[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
    for algorithm in ASYMMETRIC {
        let paddings = ASYMMETRIC_PADDINGS
            .iter()
            .filter(|padding| algorithm.paddings.contains(&padding.kind));
        for padding in paddings {
            let oids = algorithm
                .oids
                .iter()
                .find(|(p, _)| *p == padding.kind)
                .map_or(&[][..], |(_, oids)| oids);
            let kind = Kind::Asymmetric {
                algorithm,
                mode: ASYMMETRIC_MODE_NAMES[0],
                padding,
            };
            entries.push(CipherEntry::new(kind, oids));
        }
    }
    #[cfg(feature = "sm2")]
    for algorithm in MESSAGES {
        for mode in algorithm.modes {
            entries.push(CipherEntry::new(Kind::Message { algorithm, mode }, &[]));
        }
    }
    entries
});

// Splits a name such as AES/CBC/PKCS7PADDING into its three parts, as Bouncy Castle does: ASCII
// case does not matter, '-' and '_' are the same, and what a missing mode or padding gives
// depends on the kind of cipher
pub(super) fn find(name: &str) -> Option<&'static CipherEntry> {
    let mut parts = name.split('/');
    let algorithm = parts.next()?;
    let mode = parts.next().filter(|part| !part.is_empty());
    let padding = parts.next().filter(|part| !part.is_empty());
    if parts.next().is_some() {
        return None;
    }
    if let Some(algorithm) = ALGORITHMS.iter().find(|spec| known(spec.names, algorithm)) {
        return find_block(algorithm, mode, padding);
    }
    if let Some(algorithm) = STREAMS.iter().find(|spec| known(spec.names, algorithm)) {
        return find_stream(algorithm, name);
    }
    #[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
    if let Some(algorithm) = ASYMMETRIC.iter().find(|spec| known(spec.names, algorithm)) {
        return find_asymmetric(algorithm, mode, padding);
    }
    #[cfg(feature = "sm2")]
    if let Some(algorithm) = MESSAGES.iter().find(|spec| known(spec.names, algorithm)) {
        return find_message(algorithm, name, mode);
    }
    None
}

// A missing mode is ECB, and a missing padding is the mode's default
fn find_block(
    algorithm: &'static AlgorithmSpec,
    mode: Option<&str>,
    padding: Option<&str>,
) -> Option<&'static CipherEntry> {
    let mode = match mode {
        Some(mode) => MODES.iter().find(|spec| known(spec.names, mode))?,
        None => &MODES[0],
    };
    let padding = match padding {
        Some(padding) => PADDINGS.iter().find(|spec| known(spec.names, padding))?,
        None => PADDINGS
            .iter()
            .find(|spec| spec.kind == mode.default_padding())?,
    };
    CIPHERS.iter().find(|entry| {
        matches!(
            entry.kind(),
            Kind::Block { algorithm: a, mode: m, padding: p }
                if ptr::eq(*a, algorithm) && ptr::eq(*m, mode) && ptr::eq(*p, padding)
        )
    })
}

// Neither a mode nor a padding, not even an empty one, as in Bouncy Castle
fn find_stream(algorithm: &'static StreamSpec, name: &str) -> Option<&'static CipherEntry> {
    if name.contains('/') {
        return None;
    }
    CIPHERS.iter().find(|entry| {
        matches!(
            entry.kind(),
            Kind::Stream { algorithm: a } if ptr::eq(*a, algorithm)
        )
    })
}

// No mode, ECB or NONE; no padding is raw RSA, as in Bouncy Castle
#[cfg(any(feature = "rsa", feature = "elgamal", feature = "naccache-stern"))]
fn find_asymmetric(
    algorithm: &'static AsymmetricSpec,
    mode: Option<&str>,
    padding: Option<&str>,
) -> Option<&'static CipherEntry> {
    if mode.is_some_and(|mode| !known(ASYMMETRIC_MODE_NAMES, mode)) {
        return None;
    }
    let padding = match padding {
        Some(padding) => ASYMMETRIC_PADDINGS
            .iter()
            .find(|spec| known(spec.names, padding))?,
        None => &ASYMMETRIC_PADDINGS[0],
    };
    CIPHERS.iter().find(|entry| {
        matches!(
            entry.kind(),
            Kind::Asymmetric { algorithm: a, padding: p, .. }
                if ptr::eq(*a, algorithm) && ptr::eq(*p, padding)
        )
    })
}

// No mode is the first one; a padding is refused, not even an empty one
#[cfg(feature = "sm2")]
fn find_message(
    algorithm: &'static MessageSpec,
    name: &str,
    mode: Option<&str>,
) -> Option<&'static CipherEntry> {
    if name.matches('/').count() > 1 {
        return None;
    }
    let mode = match mode {
        Some(mode) => algorithm
            .modes
            .iter()
            .find(|spec| same_name(spec.name, mode))?,
        None => &algorithm.modes[0],
    };
    CIPHERS.iter().find(|entry| {
        matches!(
            entry.kind(),
            Kind::Message { algorithm: a, mode: m } if ptr::eq(*a, algorithm) && ptr::eq(*m, mode)
        )
    })
}

fn known(names: &[&str], name: &str) -> bool {
    names.iter().any(|known| same_name(known, name))
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
