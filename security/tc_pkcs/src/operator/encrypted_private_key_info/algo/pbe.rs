use tc_algo::{Algo, Params};
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid};
use tc_asn1_pkcs::{EncryptedPrivateKeyInfo, PbeParameter};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use super::to_usize;
use crate::der::{reparse, to_object};
use crate::operator::encrypted_private_key_info::{EncryptedPrivateKeyInfoEntry, PbeParams};
use crate::{DefaultPkcsOperatorContext, PkcsError};

// The PBE schemes of algo.pbe() that have an OID and a cipher behind them, PKCS#5 v1 and PKCS#12
// alike, as Bouncy Castle's EncryptedPrivateKeyInfoFactory takes them. The two write the same
// SEQUENCE of the salt and the iteration count, so both are read as a PBEParameter
pub(super) fn pbe(
    _context: &DefaultPkcsOperatorContext,
) -> Vec<Box<dyn EncryptedPrivateKeyInfoEntry>> {
    vec![Box::new(Pbe)]
}

struct Pbe;

impl EncryptedPrivateKeyInfoEntry for Pbe {
    // Written by the first OID of the scheme; a scheme without one is not this row's
    fn encrypt_by_name(
        &self,
        algo: &dyn Algo,
        name: &str,
        params: &dyn Params,
        plain: &[u8],
    ) -> Option<Result<EncryptedPrivateKeyInfo, PkcsError>> {
        let oid = algo
            .pbe()
            .algorithms()
            .find(|row| row.matches_name(name))?
            .oids()
            .first()?
            .clone();
        Some(encrypt(algo, &oid, params, plain))
    }

    fn encrypt_by_oid(
        &self,
        algo: &dyn Algo,
        oid: &Asn1Oid,
        params: &dyn Params,
        plain: &[u8],
    ) -> Option<Result<EncryptedPrivateKeyInfo, PkcsError>> {
        algo.pbe().get_by_oid(oid).ok()?;
        Some(encrypt(algo, oid, params, plain))
    }

    fn decrypt(
        &self,
        algo: &dyn Algo,
        password: &str,
        info: &EncryptedPrivateKeyInfo,
    ) -> Option<Result<Zeroizing<Vec<u8>>, PkcsError>> {
        let algorithm = info.encryption_algorithm();
        let pbe = algo.pbe().get_by_oid(algorithm.algorithm()).ok()?;
        Some(decrypt(
            algo,
            pbe.as_ref(),
            password,
            algorithm.parameters(),
            info.encrypted_data().as_bytes(),
        ))
    }
}

fn encrypt(
    algo: &dyn Algo,
    oid: &Asn1Oid,
    params: &dyn Params,
    plain: &[u8],
) -> Result<EncryptedPrivateKeyInfo, PkcsError> {
    let params = params
        .as_any()
        .downcast_ref::<PbeParams>()
        .ok_or(PkcsError::InvalidEncryptionParams)?;
    let pbe = algo.pbe().get_by_oid(oid)?;
    let key = pbe.generate_params(params.password(), params.salt(), params.iterations())?;
    let sealed = algo
        .cipher()
        .encrypt_by_name(pbe.target(), key.as_ref(), plain)?;
    let parameter = PbeParameter::new(
        Asn1OctetString::new(params.salt()),
        (params.iterations() as u64).into(),
    )?;
    Ok(EncryptedPrivateKeyInfo::new(
        AlgorithmIdentifier::with_parameters(oid.clone(), to_object(&parameter)?),
        Asn1OctetString::new(&sealed),
    ))
}

fn decrypt(
    algo: &dyn Algo,
    pbe: &dyn tc_algo::pbe::Pbe,
    password: &str,
    parameters: Option<&Asn1Object>,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PkcsError> {
    let parameter: PbeParameter = reparse(parameters)?;
    let iterations = to_usize(parameter.iteration_count())?;
    let key = pbe.generate_params(password, parameter.salt().as_bytes(), iterations)?;
    Ok(Zeroizing::new(algo.cipher().decrypt_by_name(
        pbe.target(),
        key.as_ref(),
        sealed,
    )?))
}
