//! 三張小表（block cipher 演算法、模式、padding）在第一次用到時交叉展開成合法的組合，
//! 再接上沒有模式與 padding 的 cipher（stream cipher 與獨立的 AEAD，一個演算法一列）。

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "aria")]
mod aria;
#[cfg(feature = "ascon")]
mod ascon;
#[cfg(feature = "chacha")]
mod chacha;
mod compose;
mod modes;
mod paddings;
#[cfg(feature = "rc2")]
mod rc2;
#[cfg(feature = "rc5")]
mod rc5;
#[cfg(feature = "rc6")]
mod rc6;
mod specs;

use std::sync::LazyLock;

use modes::MODES;
use paddings::PADDINGS;
use specs::{AlgorithmSpec, ModeSpec, PaddingSpec, StandaloneSpec};

use crate::cipher::{Algorithm, CipherEntry, Mode, Padding};

pub(super) use compose::create_cipher;

/// 每個演算法一列；各自的 feature 關掉時，這個演算法的組合就不會展開。
const ALGORITHMS: &[AlgorithmSpec] = &[
    #[cfg(feature = "aes")]
    aes::AES,
    #[cfg(feature = "aria")]
    aria::ARIA,
    #[cfg(feature = "rc2")]
    rc2::RC2,
    #[cfg(feature = "rc5")]
    rc5::RC5,
    #[cfg(feature = "rc5")]
    rc5::RC5_64,
    #[cfg(feature = "rc6")]
    rc6::RC6,
];

/// 沒有模式與 padding 的 cipher，一個演算法一列。
const STANDALONE: &[StandaloneSpec] = &[
    #[cfg(feature = "chacha")]
    chacha::CHACHA,
    #[cfg(feature = "chacha")]
    chacha::CHACHA7539,
    #[cfg(feature = "chacha")]
    chacha::XCHACHA20,
    #[cfg(feature = "ascon")]
    ascon::ASCON_AEAD128,
    #[cfg(feature = "ascon")]
    ascon::ASCON128,
    #[cfg(feature = "ascon")]
    ascon::ASCON128A,
    #[cfg(feature = "ascon")]
    ascon::ASCON80PQ,
];

/// 每個合法組合一列：AEAD 模式只搭 NoPadding，模式要求的區塊大小要符合；沒有模式的 cipher 接在後面。
pub(super) static CIPHERS: LazyLock<Vec<CipherEntry>> = LazyLock::new(|| {
    let mut entries = Vec::new();
    for algorithm in ALGORITHMS {
        for mode in MODES.iter().filter(|mode| mode.supports(algorithm)) {
            for padding in PADDINGS {
                if mode.is_aead() && padding.padding != Padding::NoPadding {
                    continue;
                }
                let name = format!(
                    "{}/{}/{}",
                    algorithm.names[0], mode.names[0], padding.names[0]
                );
                let oids = algorithm
                    .oids
                    .iter()
                    .find(|(m, p, _)| *m == mode.mode && *p == padding.padding)
                    .map_or(&[][..], |(_, _, oids)| oids);
                entries.push(CipherEntry::new(
                    algorithm.algorithm,
                    Some(mode.mode),
                    Some(padding.padding),
                    name,
                    oids,
                ));
            }
        }
    }
    for standalone in STANDALONE {
        entries.push(CipherEntry::new(
            standalone.algorithm,
            None,
            None,
            standalone.names[0].to_string(),
            standalone.oids,
        ));
    }
    entries
});

/// 同 BC：block cipher 沒寫模式是 ECB，沒寫 padding 依模式決定；沒有模式的 cipher 不能給模式或 padding。
pub(super) fn resolve(
    algorithm: Algorithm,
    mode: Option<Mode>,
    padding: Option<Padding>,
) -> Option<(Option<Mode>, Option<Padding>)> {
    if standalone_spec(algorithm).is_some() {
        return (mode.is_none() && padding.is_none()).then_some((None, None));
    }
    let mode = mode.unwrap_or(Mode::Ecb);
    let padding = padding.unwrap_or_else(|| mode_spec(mode).default_padding());
    Some((Some(mode), Some(padding)))
}

/// 把 `"AES/CBC/PKCS7PADDING"` 拆成三段各自查表；比對不分大小寫，`-` 與 `_` 視為相同（同 BC）。
/// 空的或沒寫的段落交給 [`resolve`] 補預設值。沒有模式的 cipher 同 BC 只接受演算法名稱，帶了 `/` 就不認。
pub(super) fn parse(name: &str) -> Option<(Algorithm, Option<Mode>, Option<Padding>)> {
    if let Some(standalone) = STANDALONE
        .iter()
        .find(|spec| spec.names.iter().any(|known| same_name(known, name)))
    {
        return Some((standalone.algorithm, None, None));
    }

    let mut parts = name.split('/');
    let algorithm = parts.next()?;
    let mode = parts.next().filter(|part| !part.is_empty());
    let padding = parts.next().filter(|part| !part.is_empty());
    if parts.next().is_some() {
        return None;
    }

    let algorithm = ALGORITHMS
        .iter()
        .find(|spec| spec.names.iter().any(|known| same_name(known, algorithm)))?
        .algorithm;
    let mode = match mode {
        Some(mode) => Some(find_mode(mode)?.mode),
        None => None,
    };
    let padding = match padding {
        Some(padding) => Some(find_padding(padding)?.padding),
        None => None,
    };
    let (mode, padding) = resolve(algorithm, mode, padding)?;
    Some((algorithm, mode, padding))
}

fn find_mode(name: &str) -> Option<&'static ModeSpec> {
    MODES
        .iter()
        .find(|spec| spec.names.iter().any(|known| same_name(known, name)))
}

fn find_padding(name: &str) -> Option<&'static PaddingSpec> {
    PADDINGS
        .iter()
        .find(|spec| spec.names.iter().any(|known| same_name(known, name)))
}

fn same_name(known: &str, name: &str) -> bool {
    let normalize = |c: char| {
        if c == '_' {
            '-'
        } else {
            c.to_ascii_uppercase()
        }
    };
    known.len() == name.len() && known.chars().map(normalize).eq(name.chars().map(normalize))
}

fn algorithm_spec(algorithm: Algorithm) -> &'static AlgorithmSpec {
    ALGORITHMS
        .iter()
        .find(|spec| spec.algorithm == algorithm)
        .expect("every algorithm in a cipher entry has a spec")
}

fn standalone_spec(algorithm: Algorithm) -> Option<&'static StandaloneSpec> {
    STANDALONE.iter().find(|spec| spec.algorithm == algorithm)
}

fn mode_spec(mode: Mode) -> &'static ModeSpec {
    MODES
        .iter()
        .find(|spec| spec.mode == mode)
        .expect("every mode has a spec")
}
