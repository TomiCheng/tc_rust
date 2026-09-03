//! x86 and x86_64 CPU-feature detection.
//!
//! The capability types remain available on non-x86 targets so callers can
//! select portable backends without duplicating architecture `cfg` checks.
//! A successful [`detect`](Sse2::detect) call returns a proof token that can be
//! passed to code whose safety contract requires the corresponding feature.

#[cfg(target_arch = "x86")]
use core::arch::x86::{__cpuid, __cpuid_count, __get_cpuid_max, _xgetbv};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__cpuid, __cpuid_count, __get_cpuid_max, _xgetbv};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const UNKNOWN: u8 = 0;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const DISABLED: u8 = 1;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const ENABLED: u8 = 2;

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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn leaf1_ecx_has(bit: u32) -> bool {
    __get_cpuid_max(0).0 >= 1 && (__cpuid(1).ecx & (1 << bit)) != 0
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn leaf1_edx_has(bit: u32) -> bool {
    __get_cpuid_max(0).0 >= 1 && (__cpuid(1).edx & (1 << bit)) != 0
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn leaf7_ebx_has(bit: u32) -> bool {
    __get_cpuid_max(0).0 >= 7 && (__cpuid_count(7, 0).ebx & (1 << bit)) != 0
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn leaf7_ecx_has(bit: u32) -> bool {
    __get_cpuid_max(0).0 >= 7 && (__cpuid_count(7, 0).ecx & (1 << bit)) != 0
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn xcr0() -> Option<u64> {
    // XGETBV is valid only when CPUID reports both XSAVE and OSXSAVE.
    if !leaf1_ecx_has(26) || !leaf1_ecx_has(27) {
        return None;
    }

    // SAFETY: the CPUID checks above establish that XGETBV is available and
    // enabled by the operating system. XCR0 is the supported register index.
    Some(unsafe { _xgetbv(0) })
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn avx_state_enabled() -> bool {
    const XMM_AND_YMM: u64 = (1 << 1) | (1 << 2);

    leaf1_ecx_has(28) && xcr0().is_some_and(|value| value & XMM_AND_YMM == XMM_AND_YMM)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn avx512_state_enabled() -> bool {
    const XMM_YMM_OPMASK_AND_ZMM: u64 = (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 7);

    leaf1_ecx_has(28)
        && xcr0().is_some_and(|value| value & XMM_YMM_OPMASK_AND_ZMM == XMM_YMM_OPMASK_AND_ZMM)
}

macro_rules! capability {
    (
        $(#[$meta:meta])*
        $name:ident,
        $cache:ident,
        feature = $feature:literal,
        env = $env:literal,
        detect = $detect:expr
    ) => {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        static $cache: AtomicU8 = AtomicU8::new(UNKNOWN);

        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(());

        impl $name {
            /// Detects the capability and returns a proof token when available.
            pub fn detect() -> Option<Self> {
                Self::is_enabled().then_some(Self(()))
            }

            /// Reports whether the capability is enabled on this processor.
            ///
            /// A matching `disable-x86-*` Cargo feature always returns `false`.
            /// With this crate's `std` feature enabled, the matching
            /// `TC_DISABLE_X86_*` environment variable has the same effect when
            /// it is present before the first call.
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            pub fn is_enabled() -> bool {
                cached(&$cache, || {
                    !cfg!(feature = $feature) && !disabled_by_env($env) && $detect
                })
            }

            /// Reports whether the capability is enabled on this processor.
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            pub const fn is_enabled() -> bool {
                false
            }
        }
    };
}

capability! {
    /// Proof that the current processor can execute AES-NI instructions.
    Aes,
    AES_CACHE,
    feature = "disable-x86-aes-ni",
    env = "TC_DISABLE_X86_AES_NI",
    detect = leaf1_ecx_has(25)
}

/// Backward-compatible name for [`Aes`].
pub type AesNi = Aes;

capability! {
    /// Proof that the processor and operating system can execute AVX2 instructions.
    ///
    /// Detection includes CPUID AVX/AVX2 flags and the XCR0 XMM/YMM state
    /// required for safely executing AVX-family instructions.
    Avx2,
    AVX2_CACHE,
    feature = "disable-x86-avx2",
    env = "TC_DISABLE_X86_AVX2",
    detect = avx_state_enabled() && leaf7_ebx_has(5)
}

capability! {
    /// Proof that BMI1 instructions are available in 64-bit mode.
    ///
    /// This matches Bouncy Castle's `Bmi1.X64` surface. It always reports
    /// unavailable on 32-bit x86, even when that processor supports BMI1.
    Bmi1X64,
    BMI1_X64_CACHE,
    feature = "disable-x86-bmi1",
    env = "TC_DISABLE_X86_BMI1",
    detect = cfg!(target_arch = "x86_64") && leaf7_ebx_has(3)
}

capability! {
    /// Proof that the current processor can execute BMI2 instructions.
    Bmi2,
    BMI2_CACHE,
    feature = "disable-x86-bmi2",
    env = "TC_DISABLE_X86_BMI2",
    detect = leaf7_ebx_has(8)
}

capability! {
    /// Proof that BMI2 instructions are available in 64-bit mode.
    Bmi2X64,
    BMI2_X64_CACHE,
    feature = "disable-x86-bmi2",
    env = "TC_DISABLE_X86_BMI2",
    detect = cfg!(target_arch = "x86_64") && leaf7_ebx_has(8)
}

capability! {
    /// Proof that 128-bit PCLMULQDQ carry-less multiplication is available.
    Pclmulqdq,
    PCLMULQDQ_CACHE,
    feature = "disable-x86-pclmulqdq",
    env = "TC_DISABLE_X86_PCLMULQDQ",
    detect = leaf1_ecx_has(1)
}

capability! {
    /// Proof that 256-bit VPCLMULQDQ carry-less multiplication is available.
    ///
    /// This requires PCLMULQDQ, VPCLMULQDQ, and operating-system support for
    /// saving XMM/YMM state.
    PclmulqdqV256,
    PCLMULQDQ_V256_CACHE,
    feature = "disable-x86-pclmulqdq-v256",
    env = "TC_DISABLE_X86_PCLMULQDQ_V256",
    detect = Pclmulqdq::is_enabled() && avx_state_enabled() && leaf7_ecx_has(10)
}

capability! {
    /// Proof that 512-bit VPCLMULQDQ carry-less multiplication is available.
    ///
    /// This additionally requires AVX-512F and operating-system support for
    /// saving opmask and ZMM state.
    PclmulqdqV512,
    PCLMULQDQ_V512_CACHE,
    feature = "disable-x86-pclmulqdq-v512",
    env = "TC_DISABLE_X86_PCLMULQDQ_V512",
    detect = Pclmulqdq::is_enabled()
        && leaf7_ecx_has(10)
        && leaf7_ebx_has(16)
        && avx512_state_enabled()
}

capability! {
    /// Proof that the current processor can execute SSE2 instructions.
    ///
    /// SSE2 is part of the x86_64 architecture baseline. On 32-bit x86 this
    /// checks CPUID leaf 1 EDX bit 26.
    Sse2,
    SSE2_CACHE,
    feature = "disable-x86-sse2",
    env = "TC_DISABLE_X86_SSE2",
    detect = cfg!(target_arch = "x86_64") || leaf1_edx_has(26)
}

capability! {
    /// Proof that the current processor can execute SSE4.1 instructions.
    Sse41,
    SSE41_CACHE,
    feature = "disable-x86-sse41",
    env = "TC_DISABLE_X86_SSE41",
    detect = leaf1_ecx_has(19)
}

capability! {
    /// Proof that the current processor can execute SSSE3 instructions.
    Ssse3,
    SSSE3_CACHE,
    feature = "disable-x86-ssse3",
    env = "TC_DISABLE_X86_SSSE3",
    detect = leaf1_ecx_has(9)
}

/// Bouncy Castle-compatible BMI1 capability grouping.
pub mod bmi1 {
    pub use super::Bmi1X64 as X64;
}

/// Bouncy Castle-compatible BMI2 capability grouping.
pub mod bmi2 {
    pub use super::Bmi2X64 as X64;
}

/// Bouncy Castle-compatible PCLMULQDQ vector-width grouping.
pub mod pclmulqdq {
    pub use super::{PclmulqdqV256 as V256, PclmulqdqV512 as V512};
}

#[cfg(test)]
mod tests {
    use super::{
        Aes, AesNi, Avx2, Bmi1X64, Bmi2, Bmi2X64, Pclmulqdq, PclmulqdqV256, PclmulqdqV512, Sse2,
        Sse41, Ssse3, bmi1, bmi2, pclmulqdq,
    };

    #[test]
    fn every_token_matches_boolean_detection() {
        assert_eq!(Aes::detect().is_some(), Aes::is_enabled());
        assert_eq!(Avx2::detect().is_some(), Avx2::is_enabled());
        assert_eq!(Bmi1X64::detect().is_some(), Bmi1X64::is_enabled());
        assert_eq!(Bmi2::detect().is_some(), Bmi2::is_enabled());
        assert_eq!(Bmi2X64::detect().is_some(), Bmi2X64::is_enabled());
        assert_eq!(Pclmulqdq::detect().is_some(), Pclmulqdq::is_enabled());
        assert_eq!(
            PclmulqdqV256::detect().is_some(),
            PclmulqdqV256::is_enabled()
        );
        assert_eq!(
            PclmulqdqV512::detect().is_some(),
            PclmulqdqV512::is_enabled()
        );
        assert_eq!(Sse2::detect().is_some(), Sse2::is_enabled());
        assert_eq!(Sse41::detect().is_some(), Sse41::is_enabled());
        assert_eq!(Ssse3::detect().is_some(), Ssse3::is_enabled());
    }

    #[test]
    fn compatibility_names_report_the_same_capabilities() {
        assert_eq!(AesNi::is_enabled(), Aes::is_enabled());
        assert_eq!(bmi1::X64::is_enabled(), Bmi1X64::is_enabled());
        assert_eq!(bmi2::X64::is_enabled(), Bmi2X64::is_enabled());
        assert_eq!(pclmulqdq::V256::is_enabled(), PclmulqdqV256::is_enabled());
        assert_eq!(pclmulqdq::V512::is_enabled(), PclmulqdqV512::is_enabled());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x64_variants_match_their_base_instruction_sets() {
        assert_eq!(Bmi2X64::is_enabled(), Bmi2::is_enabled());
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "disable-x86-sse2")))]
    #[test]
    fn x86_64_baseline_supports_sse2() {
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
    fn cargo_feature_disables_aes() {
        assert!(!Aes::is_enabled());
        assert_eq!(None, Aes::detect());
    }

    #[cfg(any(
        feature = "disable-x86-avx2",
        feature = "disable-x86-bmi1",
        feature = "disable-x86-bmi2",
        feature = "disable-x86-pclmulqdq",
        feature = "disable-x86-pclmulqdq-v256",
        feature = "disable-x86-pclmulqdq-v512",
        feature = "disable-x86-sse41",
        feature = "disable-x86-ssse3"
    ))]
    #[test]
    fn configured_cargo_features_disable_their_capabilities() {
        #[cfg(feature = "disable-x86-avx2")]
        assert!(!Avx2::is_enabled());
        #[cfg(feature = "disable-x86-bmi1")]
        assert!(!Bmi1X64::is_enabled());
        #[cfg(feature = "disable-x86-bmi2")]
        {
            assert!(!Bmi2::is_enabled());
            assert!(!Bmi2X64::is_enabled());
        }
        #[cfg(feature = "disable-x86-pclmulqdq")]
        {
            assert!(!Pclmulqdq::is_enabled());
            assert!(!PclmulqdqV256::is_enabled());
            assert!(!PclmulqdqV512::is_enabled());
        }
        #[cfg(feature = "disable-x86-pclmulqdq-v256")]
        assert!(!PclmulqdqV256::is_enabled());
        #[cfg(feature = "disable-x86-pclmulqdq-v512")]
        assert!(!PclmulqdqV512::is_enabled());
        #[cfg(feature = "disable-x86-sse41")]
        assert!(!Sse41::is_enabled());
        #[cfg(feature = "disable-x86-ssse3")]
        assert!(!Ssse3::is_enabled());
    }

    #[cfg(feature = "std")]
    #[test]
    fn runtime_environment_overrides_disable_every_capability() {
        const CHILD_MARKER: &str = "TC_RUNTIME_X86_ENV_TEST_CHILD";
        const TEST_NAME: &str =
            "intrinsics::x86::tests::runtime_environment_overrides_disable_every_capability";
        const DISABLE_VARIABLES: &[&str] = &[
            "TC_DISABLE_X86_AES_NI",
            "TC_DISABLE_X86_AVX2",
            "TC_DISABLE_X86_BMI1",
            "TC_DISABLE_X86_BMI2",
            "TC_DISABLE_X86_PCLMULQDQ",
            "TC_DISABLE_X86_PCLMULQDQ_V256",
            "TC_DISABLE_X86_PCLMULQDQ_V512",
            "TC_DISABLE_X86_SSE2",
            "TC_DISABLE_X86_SSE41",
            "TC_DISABLE_X86_SSSE3",
        ];

        if std::env::var_os(CHILD_MARKER).is_some() {
            assert!(!Aes::is_enabled());
            assert!(!Avx2::is_enabled());
            assert!(!Bmi1X64::is_enabled());
            assert!(!Bmi2::is_enabled());
            assert!(!Bmi2X64::is_enabled());
            assert!(!Pclmulqdq::is_enabled());
            assert!(!PclmulqdqV256::is_enabled());
            assert!(!PclmulqdqV512::is_enabled());
            assert!(!Sse2::is_enabled());
            assert!(!Sse41::is_enabled());
            assert!(!Ssse3::is_enabled());
            return;
        }

        let mut child = std::process::Command::new(
            std::env::current_exe().expect("current test executable should be available"),
        );
        child
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_MARKER, "1");
        for variable in DISABLE_VARIABLES {
            child.env(variable, "1");
        }

        let status = child.status().expect("environment test child should run");
        assert!(status.success());
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn non_x86_targets_report_every_capability_as_unavailable() {
        assert!(!Aes::is_enabled());
        assert!(!Avx2::is_enabled());
        assert!(!Bmi1X64::is_enabled());
        assert!(!Bmi2::is_enabled());
        assert!(!Bmi2X64::is_enabled());
        assert!(!Pclmulqdq::is_enabled());
        assert!(!PclmulqdqV256::is_enabled());
        assert!(!PclmulqdqV512::is_enabled());
        assert!(!Sse2::is_enabled());
        assert!(!Sse41::is_enabled());
        assert!(!Ssse3::is_enabled());
    }
}
