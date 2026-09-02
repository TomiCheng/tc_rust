//! x86 and x86_64 CPU-feature detection.
//!
//! The types in this module remain available on non-x86 targets so callers can
//! select a portable backend without duplicating architecture `cfg` checks.

#[cfg(target_arch = "x86")]
use core::arch::x86::{__cpuid, __get_cpuid_max};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__cpuid, __get_cpuid_max};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const UNKNOWN: u8 = 0;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const DISABLED: u8 = 1;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const ENABLED: u8 = 2;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static SSE2_CACHE: AtomicU8 = AtomicU8::new(UNKNOWN);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static AES_NI_CACHE: AtomicU8 = AtomicU8::new(UNKNOWN);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cached(cache: &AtomicU8, detect: impl FnOnce() -> bool) -> bool {
    match cache.load(Ordering::Relaxed) {
        ENABLED => true,
        DISABLED => false,
        UNKNOWN => {
            let enabled = detect();
            cache.store(if enabled { ENABLED } else { DISABLED }, Ordering::Relaxed);
            enabled
        }
        _ => unreachable!(),
    }
}

#[cfg(feature = "std")]
fn disabled_by_env(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

#[cfg(not(feature = "std"))]
const fn disabled_by_env(_name: &str) -> bool {
    false
}

/// Proof that the current processor can execute SSE2 instructions.
///
/// Construct this token with [`Sse2::detect`]. Its private field prevents code
/// from claiming SSE2 support without first running the platform-specific
/// detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sse2(());

impl Sse2 {
    /// Detects SSE2 and returns a proof token when it is available.
    pub fn detect() -> Option<Self> {
        Self::is_enabled().then_some(Self(()))
    }

    /// Reports whether the current processor can execute SSE2 instructions.
    ///
    /// The `disable-x86-sse2` Cargo feature always disables this capability.
    /// With the `std` feature enabled, setting `TC_DISABLE_X86_SSE2` before
    /// the first call also disables it for the lifetime of the process.
    ///
    /// SSE2 is part of the x86_64 architecture baseline. On 32-bit x86 this
    /// checks CPUID leaf 1 EDX bit 26. Other architectures return `false`.
    #[cfg(target_arch = "x86_64")]
    pub fn is_enabled() -> bool {
        cached(&SSE2_CACHE, || {
            !cfg!(feature = "disable-x86-sse2") && !disabled_by_env("TC_DISABLE_X86_SSE2")
        })
    }

    /// Reports whether the current processor can execute SSE2 instructions.
    #[cfg(target_arch = "x86")]
    pub fn is_enabled() -> bool {
        cached(&SSE2_CACHE, || {
            !cfg!(feature = "disable-x86-sse2")
                && !disabled_by_env("TC_DISABLE_X86_SSE2")
                && __get_cpuid_max(0).0 >= 1
                && (__cpuid(1).edx & (1 << 26)) != 0
        })
    }

    /// Reports whether the current processor can execute SSE2 instructions.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    pub const fn is_enabled() -> bool {
        false
    }
}

/// Proof that the current processor can execute AES-NI instructions.
///
/// Construct this token with [`AesNi::detect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesNi(());

impl AesNi {
    /// Detects AES-NI and returns a proof token when it is available.
    pub fn detect() -> Option<Self> {
        Self::is_enabled().then_some(Self(()))
    }

    /// Reports whether the current processor can execute AES-NI instructions.
    ///
    /// The `disable-x86-aes-ni` Cargo feature always disables this capability.
    /// With the `std` feature enabled, setting `TC_DISABLE_X86_AES_NI` before
    /// the first call also disables it for the lifetime of the process.
    ///
    /// On x86 and x86_64 this checks CPUID leaf 1 ECX bit 25. Other
    /// architectures return `false`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn is_enabled() -> bool {
        cached(&AES_NI_CACHE, || {
            !cfg!(feature = "disable-x86-aes-ni")
                && !disabled_by_env("TC_DISABLE_X86_AES_NI")
                && __get_cpuid_max(0).0 >= 1
                && (__cpuid(1).ecx & (1 << 25)) != 0
        })
    }

    /// Reports whether the current processor can execute AES-NI instructions.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    pub const fn is_enabled() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{AesNi, Sse2};

    #[test]
    fn token_matches_boolean_detection() {
        assert_eq!(Sse2::detect().is_some(), Sse2::is_enabled());
        assert_eq!(AesNi::detect().is_some(), AesNi::is_enabled());
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "disable-x86-sse2")))]
    #[test]
    fn x86_64_always_supports_sse2() {
        assert!(Sse2::is_enabled());
    }

    #[cfg(feature = "disable-x86-sse2")]
    #[test]
    fn cargo_feature_disables_sse2() {
        assert!(!Sse2::is_enabled());
        assert_eq!(None, Sse2::detect());
    }

    #[cfg(feature = "disable-x86-aes-ni")]
    #[test]
    fn cargo_feature_disables_aes_ni() {
        assert!(!AesNi::is_enabled());
        assert_eq!(None, AesNi::detect());
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn non_x86_targets_report_sse2_as_unavailable() {
        assert!(!Sse2::is_enabled());
    }
}
