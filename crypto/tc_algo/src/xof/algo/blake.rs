use super::init_xof::{InitXof, invalid};
use super::row::row;
use crate::DefaultAlgoContext;
use crate::xof::XofEntry;

// The rows of BLAKE2xs and BLAKE3, to give to DefaultAlgoBuilder::reg_xof. Bouncy Castle has no
// factory of XOFs, so they are named after their XOFs, with no alias or OID. Init gives BLAKE2xs a
// key, salt or personalization, and BLAKE3 a key or a context for key derivation

#[cfg(feature = "blake2xs")]
pub(super) fn blake2xs(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("BLAKE2XS", &[], &[], || {
        Box::new(InitXof::new(
            tc_blake::Blake2xsDigest::new(),
            |params: &crate::params::Blake2xsParams| {
                // BLAKE2s's limits, which tc_blake panics past
                let key_fits = params.key().is_none_or(|key| key.len() <= 32);
                let salt_fits = params.salt().is_none_or(|salt| salt.len() == 8);
                let personalization_fits = params
                    .personalization()
                    .is_none_or(|personalization| personalization.len() == 8);
                if !(key_fits && salt_fits && personalization_fits) {
                    return Err(invalid());
                }
                Ok(tc_blake::Blake2xsDigest::with_parameters(
                    tc_blake::Blake2xsDigest::UNKNOWN_DIGEST_LENGTH,
                    params.key(),
                    params.salt(),
                    params.personalization(),
                ))
            },
        ))
    })
}

#[cfg(feature = "blake3")]
pub(super) fn blake3(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("BLAKE3", &[], &[], || {
        Box::new(InitXof::new(
            tc_blake::Blake3Digest::new(),
            |params: &crate::params::Blake3Params| match (params.key(), params.context()) {
                (Some(key), _) if key.len() == 32 => Ok(tc_blake::Blake3Digest::with_key(256, key)),
                (None, Some(context)) => Ok(tc_blake::Blake3Digest::with_derive_key(256, context)),
                _ => Err(invalid()),
            },
        ))
    })
}

#[cfg(test)]
mod tests {
    use crate::DefaultAlgoContext;
    use crate::xof::XofEntry;

    // The row gives the output of the XOF it wraps, taken in pieces
    fn check(rows: Vec<Box<dyn XofEntry>>, mut direct: impl tc_digest::Xof) {
        let mut xof = rows[0].create();
        xof.try_update(b"a").unwrap();
        xof.try_update(b"bc").unwrap();
        let mut first = [0; 40];
        xof.try_output(&mut first).unwrap();
        let output = [&first[..], &xof.finalize_len(60).unwrap()].concat();

        direct.update(b"abc");
        let mut expected = vec![0; 100];
        direct.output_final(&mut expected);
        assert_eq!(output, expected);
    }

    // The name and every alias and OID of the row find it through the factory
    fn find(name: &str, aliases: &[&str], oids: &[&str]) {
        use crate::AlgoBuilder as _;
        let algo = crate::DefaultAlgoBuilder::default().build();
        for name in std::iter::once(&name).chain(aliases) {
            assert!(algo.xof().get_by_name(name).is_ok(), "{name}");
        }
        for oid in oids {
            assert!(
                algo.xof().get_by_oid(&oid.parse().unwrap()).is_ok(),
                "{oid}"
            );
        }
    }

    #[cfg(feature = "blake2xs")]
    #[test]
    fn the_blake2xs_row_gives_the_output_of_its_xof_and_is_found_by_its_names() {
        check(
            super::blake2xs(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2xsDigest::new(),
        );
        find("BLAKE2XS", &[], &[]);
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn the_blake3_row_gives_the_output_of_its_xof_and_is_found_by_its_names() {
        check(
            super::blake3(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake3Digest::new(),
        );
        find("BLAKE3", &[], &[]);
    }

    #[cfg(feature = "blake2xs")]
    #[test]
    fn blake2xs_takes_a_key_salt_and_personalization_of_their_lengths_from_init() {
        use crate::params::Blake2xsParams;
        use crate::{AlgoBuilder as _, ErrorKind};

        let algo = crate::DefaultAlgoBuilder::default().build();
        let mut xof = algo.xof().get_by_name("BLAKE2XS").unwrap();
        let params = Blake2xsParams::new()
            .with_key(vec![1; 32])
            .with_salt(vec![2; 8])
            .with_personalization(vec![3; 8]);
        xof.init(&params).unwrap();
        xof.try_update(b"abc").unwrap();
        let mut direct = tc_blake::Blake2xsDigest::with_parameters(
            tc_blake::Blake2xsDigest::UNKNOWN_DIGEST_LENGTH,
            Some(&[1; 32]),
            Some(&[2; 8]),
            Some(&[3; 8]),
        );
        tc_digest::Digest::update(&mut direct, b"abc");
        let mut expected = vec![0; 100];
        tc_digest::Xof::output_final(&mut direct, &mut expected);
        assert_eq!(xof.finalize_len(100).unwrap(), expected);

        for params in [
            Blake2xsParams::new().with_key(vec![0; 33]),
            Blake2xsParams::new().with_salt(vec![0; 7]),
            Blake2xsParams::new().with_personalization(vec![0; 9]),
        ] {
            let error = xof.init(&params).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams);
        }
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_takes_a_32_byte_key_or_a_context_from_init() {
        use crate::params::Blake3Params;
        use crate::{AlgoBuilder as _, ErrorKind};

        let algo = crate::DefaultAlgoBuilder::default().build();
        let mut xof = algo.xof().get_by_name("BLAKE3").unwrap();
        let cases = [
            (
                Blake3Params::keyed(vec![7; 32]),
                tc_blake::Blake3Digest::with_key(256, &[7; 32]),
            ),
            (
                Blake3Params::derive_key(b"app 2026 session".to_vec()),
                tc_blake::Blake3Digest::with_derive_key(256, b"app 2026 session"),
            ),
        ];
        for (params, mut direct) in cases {
            xof.init(&params).unwrap();
            xof.try_update(b"abc").unwrap();
            tc_digest::Digest::update(&mut direct, b"abc");
            let mut expected = vec![0; 100];
            tc_digest::Xof::output_final(&mut direct, &mut expected);
            assert_eq!(xof.finalize_len(100).unwrap(), expected);
        }

        let error = xof.init(&Blake3Params::keyed(vec![0; 31])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
