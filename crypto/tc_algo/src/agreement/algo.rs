#[cfg(feature = "cfrg-curves")]
mod cfrg;
#[cfg(feature = "dh")]
mod dh;
#[cfg(any(
    all(
        feature = "ecdh",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecmqv",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    )
))]
mod ec;
#[cfg(any(
    all(
        feature = "ecdh",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecmqv",
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
    feature = "cfrg-curves"
))]
mod typed;
#[cfg(all(
    feature = "ecgost3410",
    any(
        feature = "fp-custom",
        feature = "fp-curve",
        feature = "f2m-custom",
        feature = "f2m-curve"
    )
))]
mod vko;

use super::AgreementEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the agreements whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "dh")]
    dh::dh,
    #[cfg(any(
        all(
            feature = "ecdh",
            any(
                feature = "fp-custom",
                feature = "fp-curve",
                feature = "f2m-custom",
                feature = "f2m-curve"
            )
        ),
        all(
            feature = "ecmqv",
            any(
                feature = "fp-custom",
                feature = "fp-curve",
                feature = "f2m-custom",
                feature = "f2m-curve"
            )
        )
    ))]
    ec::ec,
    #[cfg(all(
        feature = "ecgost3410",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ))]
    vko::vko,
    #[cfg(feature = "cfrg-curves")]
    cfrg::cfrg,
];
