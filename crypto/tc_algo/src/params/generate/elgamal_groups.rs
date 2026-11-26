//! The groups of `dh_groups` as `ElGamalParameters`, with the same names.

use tc_dh_key::{DhParameters, standard_groups as dh};
use tc_elgamal::ElGamalParameters;

fn from_dh(group: DhParameters) -> ElGamalParameters {
    ElGamalParameters::new(group.p().clone(), group.g().clone()).with_l(group.l())
}

/// The group `rfc2409_768` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc2409_768() -> ElGamalParameters {
    from_dh(dh::rfc2409_768())
}

/// The group `rfc2409_1024` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc2409_1024() -> ElGamalParameters {
    from_dh(dh::rfc2409_1024())
}

/// The group `rfc3526_1536` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc3526_1536() -> ElGamalParameters {
    from_dh(dh::rfc3526_1536())
}

/// The group `rfc3526_2048` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc3526_2048() -> ElGamalParameters {
    from_dh(dh::rfc3526_2048())
}

/// The group `rfc3526_3072` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc3526_3072() -> ElGamalParameters {
    from_dh(dh::rfc3526_3072())
}

/// The group `rfc3526_4096` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc3526_4096() -> ElGamalParameters {
    from_dh(dh::rfc3526_4096())
}

/// The group `rfc3526_6144` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc3526_6144() -> ElGamalParameters {
    from_dh(dh::rfc3526_6144())
}

/// The group `rfc3526_8192` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc3526_8192() -> ElGamalParameters {
    from_dh(dh::rfc3526_8192())
}

/// The group `rfc7919_ffdhe2048` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc7919_ffdhe2048() -> ElGamalParameters {
    from_dh(dh::rfc7919_ffdhe2048())
}

/// The group `rfc7919_ffdhe3072` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc7919_ffdhe3072() -> ElGamalParameters {
    from_dh(dh::rfc7919_ffdhe3072())
}

/// The group `rfc7919_ffdhe4096` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc7919_ffdhe4096() -> ElGamalParameters {
    from_dh(dh::rfc7919_ffdhe4096())
}

/// The group `rfc7919_ffdhe6144` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc7919_ffdhe6144() -> ElGamalParameters {
    from_dh(dh::rfc7919_ffdhe6144())
}

/// The group `rfc7919_ffdhe8192` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc7919_ffdhe8192() -> ElGamalParameters {
    from_dh(dh::rfc7919_ffdhe8192())
}

/// The group `rfc4306_768` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc4306_768() -> ElGamalParameters {
    from_dh(dh::rfc4306_768())
}

/// The group `rfc4306_1024` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc4306_1024() -> ElGamalParameters {
    from_dh(dh::rfc4306_1024())
}

/// The group `rfc5996_768` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc5996_768() -> ElGamalParameters {
    from_dh(dh::rfc5996_768())
}

/// The group `rfc5996_1024` of `dh_groups`, with its private value length. Variable time: only public constants.
pub fn rfc5996_1024() -> ElGamalParameters {
    from_dh(dh::rfc5996_1024())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_group_keeps_the_modulus_generator_and_private_value_length_of_its_dh_group() {
        let pairs: [(ElGamalParameters, DhParameters); 17] = [
            (rfc2409_768(), dh::rfc2409_768()),
            (rfc2409_1024(), dh::rfc2409_1024()),
            (rfc3526_1536(), dh::rfc3526_1536()),
            (rfc3526_2048(), dh::rfc3526_2048()),
            (rfc3526_3072(), dh::rfc3526_3072()),
            (rfc3526_4096(), dh::rfc3526_4096()),
            (rfc3526_6144(), dh::rfc3526_6144()),
            (rfc3526_8192(), dh::rfc3526_8192()),
            (rfc7919_ffdhe2048(), dh::rfc7919_ffdhe2048()),
            (rfc7919_ffdhe3072(), dh::rfc7919_ffdhe3072()),
            (rfc7919_ffdhe4096(), dh::rfc7919_ffdhe4096()),
            (rfc7919_ffdhe6144(), dh::rfc7919_ffdhe6144()),
            (rfc7919_ffdhe8192(), dh::rfc7919_ffdhe8192()),
            (rfc4306_768(), dh::rfc4306_768()),
            (rfc4306_1024(), dh::rfc4306_1024()),
            (rfc5996_768(), dh::rfc5996_768()),
            (rfc5996_1024(), dh::rfc5996_1024()),
        ];
        for (elgamal, dh) in pairs {
            assert_eq!(elgamal.p(), dh.p());
            assert_eq!(elgamal.g(), dh.g());
            assert_eq!(elgamal.l(), dh.l());
        }
    }
}
