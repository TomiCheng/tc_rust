mod interleave;
mod squarer;
#[cfg(target_arch = "x86_64")]
mod x86;

pub(crate) use squarer::Squarer;
