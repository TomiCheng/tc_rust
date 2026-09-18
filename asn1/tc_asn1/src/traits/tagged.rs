/// The universal identifier a type reads and writes by itself, for callers
/// that must recognize the type before decoding it (an OPTIONAL field).
pub trait Tagged {
    const TAG: &'static [u8];
}
