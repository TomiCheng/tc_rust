#[allow(unused_imports, reason = "each family uses some")]
use rand_core::CryptoRng;
#[allow(unused_imports, reason = "each family uses some")]
use tc_asym_cipher::{KeyPairGenerator as _, KeyPairGeneratorInit as _};

#[allow(unused_imports, reason = "each family uses some")]
use super::with_params::{Pair, Row, downcast, invalid_params, refuse};
use crate::DefaultAlgoContext;
use crate::generate::KeyPairGeneratorEntry;
#[allow(unused_imports, reason = "each family uses some")]
use crate::{AlgoError, ErrorKind, Params};

// The key pair generators of the signers: DSA, GOST R 34.10-94, Ed25519, Ed448, ML-DSA and SLH-DSA,
// with the names, aliases and OIDs of Bouncy Castle's GeneratorUtilities
pub(super) fn signing_keys(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>> {
    #[allow(unused_variables, reason = "unused when no family is on")]
    let rand = context.rand();
    #[allow(unused_mut, reason = "empty when no family is on")]
    let mut rows: Vec<Box<dyn KeyPairGeneratorEntry>> = Vec::new();

    // Over a domain: a DsaParameters, or a DsaKeyGenParams to generate one at init
    #[cfg(feature = "dsa")]
    rows.push(Box::new(Row::new(
        "DSA",
        &[],
        &[],
        rand,
        |params, rand| {
            use tc_dsa_signer::{DsaGroupGenerationParams, DsaGroupGenerator};

            if let Some(domain) = downcast::<tc_dsa_signer::DsaParameters>(params) {
                return Ok(domain);
            }
            let params = params
                .as_any()
                .downcast_ref::<crate::params::generate::DsaKeyGenParams>()
                .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
            let mut generator = DsaGroupGenerator::with_digest(rand, tc_sha::Sha256Digest::new());
            generator
                .init_fips186_3(&DsaGroupGenerationParams::new(
                    params.l(),
                    params.n(),
                    params.certainty(),
                ))
                .map_err(invalid_params)?;
            generator.generate_group().map_err(invalid_params)
        },
        |rand, domain| {
            let mut generator = tc_dsa_signer::DsaKeyPairGenerator::new(rand);
            generator
                .init(&tc_dsa_signer::DsaKeyGenerationParams::new(domain.clone()))
                .map_err(invalid_params)?;
            let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
            Ok((Box::new(public), Box::new(private)))
        },
    )));

    // Over a domain: a Gost3410Parameters, or a Gost3410KeyGenParams to generate one at init
    #[cfg(feature = "gost3410")]
    rows.push(Box::new(Row::new(
        "GOST3410",
        &["GOST-3410", "GOST-3410-94"],
        &[],
        rand,
        |params, rand| {
            if let Some(domain) = downcast::<tc_gost3410::Gost3410Parameters>(params) {
                return Ok(domain);
            }
            let params = params
                .as_any()
                .downcast_ref::<crate::params::generate::Gost3410KeyGenParams>()
                .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
            let mut generator = tc_gost3410::Gost3410GroupGenerator::new(rand);
            generator.init(params.size(), 2).map_err(invalid_params)?;
            generator.generate_group().map_err(invalid_params)
        },
        |rand, domain| {
            let mut generator = tc_gost3410::Gost3410KeyPairGenerator::new(rand);
            generator
                .init(&tc_gost3410::Gost3410KeyGenerationParams::new(
                    domain.clone(),
                ))
                .map_err(invalid_params)?;
            let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
            Ok((Box::new(public), Box::new(private)))
        },
    )));

    // No params: the curve is fixed
    #[cfg(feature = "cfrg-curves")]
    rows.push(Box::new(
        Row::<()>::new(
            "Ed25519",
            &["Ed25519ctx", "Ed25519ph"],
            &["1.3.101.112"],
            rand,
            refuse,
            |rand, ()| {
                let mut generator = tc_cfrg_curves::Ed25519KeyPairGenerator::new(rand);
                generator
                    .init(&tc_cfrg_curves::KeyGenerationParams::new())
                    .map_err(invalid_params)?;
                let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
                Ok((Box::new(public), Box::new(private)))
            },
        )
        .with_default(|| ()),
    ));
    #[cfg(feature = "cfrg-curves")]
    rows.push(Box::new(
        Row::<()>::new(
            "Ed448",
            &["Ed448ph"],
            &["1.3.101.113"],
            rand,
            refuse,
            |rand, ()| {
                let mut generator = tc_cfrg_curves::Ed448KeyPairGenerator::new(rand);
                generator
                    .init(&tc_cfrg_curves::KeyGenerationParams::new())
                    .map_err(invalid_params)?;
                let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
                Ok((Box::new(public), Box::new(private)))
            },
        )
        .with_default(|| ()),
    ));

    // Over a parameter set, which has no default
    #[cfg(feature = "ml-dsa")]
    rows.push(Box::new(Row::new(
        "ML-DSA",
        &[],
        &[],
        rand,
        |params, _| {
            downcast::<tc_ml_dsa::MlDsaParameters>(params)
                .ok_or(AlgoError::new(ErrorKind::InvalidParams))
        },
        |rand, set| {
            let mut generator = tc_ml_dsa::MlDsaKeyPairGenerator::new(rand);
            generator
                .init(&tc_ml_dsa::MlDsaKeyGenerationParams::new(*set))
                .map_err(invalid_params)?;
            let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
            Ok((Box::new(public), Box::new(private)))
        },
    )));
    #[cfg(feature = "slh-dsa")]
    rows.push(Box::new(Row::new(
        "SLH-DSA",
        &[],
        &[],
        rand,
        |params, _| {
            downcast::<tc_slh_dsa::SlhDsaParameters>(params)
                .ok_or(AlgoError::new(ErrorKind::InvalidParams))
        },
        |rand, set| {
            let mut generator = tc_slh_dsa::SlhDsaKeyPairGenerator::new(rand);
            generator
                .init(&tc_slh_dsa::SlhDsaKeyGenerationParams::new(*set))
                .map_err(invalid_params)?;
            let (public, private) = generator.generate_key_pair().map_err(invalid_params)?;
            Ok((Box::new(public), Box::new(private)))
        },
    )));

    rows
}
