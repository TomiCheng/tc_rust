//! `standard_groups`：BC `DHStandardGroups` 的群組都是 g = 2、q = (p − 1) / 2 的安全質數
//! 群組，私鑰位元數照 BC。

use tc_bigint::BigUint;
use tc_dh_key::DhParameters;
use tc_dh_key::standard_groups::*;
use tc_prime::Primality;

/// 群組、p 的位元數與 l。
type Group = (fn() -> DhParameters, u32, u32);

fn big(value: &tc_bigint::PaddedBigUint) -> BigUint {
    BigUint::from(value.clone())
}

#[test]
fn every_group_is_a_valid_safe_prime_group_of_its_size_with_bc_s_lengths() {
    let groups: [Group; 13] = [
        (rfc2409_768, 768, 0),
        (rfc2409_1024, 1024, 0),
        (rfc3526_1536, 1536, 200),
        (rfc3526_2048, 2048, 225),
        (rfc3526_3072, 3072, 275),
        (rfc3526_4096, 4096, 325),
        (rfc3526_6144, 6144, 375),
        (rfc3526_8192, 8192, 400),
        (rfc7919_ffdhe2048, 2048, 225),
        (rfc7919_ffdhe3072, 3072, 275),
        (rfc7919_ffdhe4096, 4096, 325),
        (rfc7919_ffdhe6144, 6144, 375),
        (rfc7919_ffdhe8192, 8192, 400),
    ];
    for (group, bits, l) in groups {
        let params = group();
        let p = big(params.p());
        assert_eq!(p.bits(), bits);
        assert_eq!(big(params.g()), BigUint::from(2u8));
        assert_eq!(big(params.q().unwrap()), &p >> 1);
        assert_eq!(params.l(), l);
        assert_eq!(params.m(), if l == 0 { 160 } else { l.min(160) });
        assert_eq!(params.validate(), Ok(()), "{bits} bits");
    }
}

#[test]
fn the_smaller_groups_are_safe_primes() {
    let mut rng = rand::rng();
    for group in [
        rfc2409_768,
        rfc2409_1024,
        rfc3526_1536,
        rfc3526_2048,
        rfc7919_ffdhe2048,
    ] {
        let params = group();
        assert!(big(params.p()).is_probable_prime(4, &mut rng));
        assert!(big(params.q().unwrap()).is_probable_prime(4, &mut rng));
    }
}

#[test]
fn the_rfc_4306_and_5996_names_are_the_rfc_2409_groups() {
    assert_eq!(rfc4306_768(), rfc2409_768());
    assert_eq!(rfc4306_1024(), rfc2409_1024());
    assert_eq!(rfc5996_768(), rfc2409_768());
    assert_eq!(rfc5996_1024(), rfc2409_1024());
}
