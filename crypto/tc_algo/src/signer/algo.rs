#[cfg(any(
    feature = "dsa",
    all(
        feature = "ecdsa",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecnr",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    )
))]
mod digest_dsa;
#[cfg(feature = "dsa")]
mod dsa;
#[cfg(any(
    all(
        feature = "ecdsa",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecnr",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecgost3410",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    )
))]
mod ec;
#[cfg(feature = "cfrg-curves")]
mod eddsa;
#[cfg(feature = "gost3410")]
mod gost3410;
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
mod pqc;
#[cfg(any(
    feature = "rsa",
    feature = "dsa",
    all(
        feature = "ecdsa",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecnr",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecgost3410",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    feature = "gost3410",
    feature = "sm2",
    feature = "cfrg-curves",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
mod row;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "sm2")]
mod sm2;

use super::SignerEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the signers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "rsa")]
    rsa::rsa,
    #[cfg(feature = "dsa")]
    dsa::dsa,
    #[cfg(any(
        all(
            feature = "ecdsa",
            any(
                feature = "fp-custom",
                feature = "fp-curve",
                feature = "f2m-custom",
                feature = "f2m-curve"
            )
        ),
        all(
            feature = "ecnr",
            any(
                feature = "fp-custom",
                feature = "fp-curve",
                feature = "f2m-custom",
                feature = "f2m-curve"
            )
        ),
        all(
            feature = "ecgost3410",
            any(
                feature = "fp-custom",
                feature = "fp-curve",
                feature = "f2m-custom",
                feature = "f2m-curve"
            )
        )
    ))]
    ec::ec,
    #[cfg(feature = "gost3410")]
    gost3410::gost3410,
    #[cfg(feature = "sm2")]
    sm2::sm2,
    #[cfg(feature = "cfrg-curves")]
    eddsa::eddsa,
    #[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
    pqc::pqc,
];
