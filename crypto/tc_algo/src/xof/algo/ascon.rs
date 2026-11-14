#[cfg(feature = "ascon-cxof128")]
use super::init_xof::{InitXof, invalid};
#[cfg(any(
    feature = "ascon-xof128",
    feature = "ascon-xof",
    feature = "ascon-xofa"
))]
use super::row::TcXof;
use super::row::row;
use crate::DefaultAlgoContext;
use crate::xof::XofEntry;

// The rows of Ascon-XOF128 and Ascon-CXOF128, and the Ascon-Xof and Ascon-XofA of before NIST's
// SP 800-232, to give to DefaultAlgoBuilder::reg_xof. Bouncy Castle has no factory of XOFs, so
// they are named after their XOFs, with no alias or OID

#[cfg(feature = "ascon-xof128")]
pub(super) fn ascon_xof128(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("ASCON-XOF128", &[], &[], || {
        Box::new(TcXof(tc_ascon_hash::AsconXof128::new()))
    })
}

#[cfg(feature = "ascon-cxof128")]
pub(super) fn ascon_cxof128(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("ASCON-CXOF128", &[], &[], || {
        Box::new(InitXof::new(
            tc_ascon_hash::AsconCXof128::new(),
            |params: &crate::params::AsconCXofParams| {
                // SP 800-232's limit on Z, which tc_ascon_hash panics past
                if params.customization().len() > 256 {
                    return Err(invalid());
                }
                Ok(tc_ascon_hash::AsconCXof128::with_customization(
                    params.customization(),
                ))
            },
        ))
    })
}

#[cfg(feature = "ascon-xof")]
#[allow(deprecated)]
pub(super) fn ascon_xof(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("ASCON-XOF", &[], &[], || {
        Box::new(TcXof(tc_ascon_hash::AsconXof::new(
            tc_ascon_hash::AsconXofParameters::AsconXof,
        )))
    })
}

#[cfg(feature = "ascon-xofa")]
#[allow(deprecated)]
pub(super) fn ascon_xofa(_context: &DefaultAlgoContext) -> Vec<Box<dyn XofEntry>> {
    row("ASCON-XOFA", &[], &[], || {
        Box::new(TcXof(tc_ascon_hash::AsconXof::new(
            tc_ascon_hash::AsconXofParameters::AsconXofA,
        )))
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

    #[cfg(feature = "ascon-xof128")]
    #[test]
    fn the_ascon_xof128_row_gives_the_output_of_its_xof_and_is_found_by_its_names() {
        check(
            super::ascon_xof128(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::AsconXof128::new(),
        );
        find("ASCON-XOF128", &[], &[]);
    }

    #[cfg(feature = "ascon-xof")]
    #[allow(deprecated)]
    #[test]
    fn the_ascon_xof_row_gives_the_output_of_its_xof_and_is_found_by_its_names() {
        check(
            super::ascon_xof(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::AsconXof::new(tc_ascon_hash::AsconXofParameters::AsconXof),
        );
        find("ASCON-XOF", &[], &[]);
    }

    #[cfg(feature = "ascon-xofa")]
    #[allow(deprecated)]
    #[test]
    fn the_ascon_xofa_row_gives_the_output_of_its_xof_and_is_found_by_its_names() {
        check(
            super::ascon_xofa(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::AsconXof::new(tc_ascon_hash::AsconXofParameters::AsconXofA),
        );
        find("ASCON-XOFA", &[], &[]);
    }

    #[cfg(feature = "ascon-cxof128")]
    #[test]
    fn ascon_cxof128_takes_its_customization_from_init_up_to_256_bytes() {
        use crate::params::AsconCXofParams;
        use crate::{AlgoBuilder as _, ErrorKind};

        check(
            super::ascon_cxof128(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::AsconCXof128::new(),
        );
        find("ASCON-CXOF128", &[], &[]);

        let algo = crate::DefaultAlgoBuilder::default().build();
        let mut xof = algo.xof().get_by_name("ASCON-CXOF128").unwrap();
        let params = AsconCXofParams::new().with_customization(b"Z".to_vec());
        xof.init(&params).unwrap();
        xof.try_update(b"abc").unwrap();
        let mut direct = tc_ascon_hash::AsconCXof128::with_customization(b"Z");
        tc_digest::Digest::update(&mut direct, b"abc");
        let mut expected = vec![0; 32];
        tc_digest::Xof::output_final(&mut direct, &mut expected);
        assert_eq!(xof.finalize_len(32).unwrap(), expected);

        let too_long = AsconCXofParams::new().with_customization(vec![0; 257]);
        let error = xof.init(&too_long).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
