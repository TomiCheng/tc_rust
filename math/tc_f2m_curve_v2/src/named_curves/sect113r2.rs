use super::hex::hex;
use super::{F2mNamedCurve, Taps};

/// SEC 2 sect113r2.
pub const SECT113R2: F2mNamedCurve<15> = F2mNamedCurve {
    m: 113,
    taps: Taps::Trinomial(9),
    a: hex("00689918dbec7e5a0dd6dfc0aa55c7"),
    b: hex("0095e9a9ec9b297bd4bf36e059184f"),
    order: hex("010000000000000108789b2496af93"),
    cofactor: 2,
    gx: hex("01a57a6a7b26ca5ef52fcdb8164797"),
    gy: hex("00b3adc94ed1fe674c06e695baba1d"),
};
