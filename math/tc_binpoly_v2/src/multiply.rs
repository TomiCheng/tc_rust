mod multiplier;
mod scalar;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

pub(crate) use multiplier::Multiplier;
