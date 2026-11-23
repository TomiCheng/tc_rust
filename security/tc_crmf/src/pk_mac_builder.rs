use rand::rngs::SysRng;
use rand_core::TryCryptoRng;
use tc_algo::{digest::DigestProvider, mac::MacProvider, params::key::KeyOwned};
use tc_asn1::{Asn1Integer, Asn1Null, Asn1OctetString};
use tc_asn1_cmp::{PbmParameter, crmf::CrmfId};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use crate::{CrmfError, der};

const DEFAULT_MAX_ITERATIONS: i32 = 1_000_000;

pub struct PkMacBuilder<'a> {
    digests: &'a dyn DigestProvider,
    macs: &'a dyn MacProvider,
    algorithms: Option<(AlgorithmIdentifier, AlgorithmIdentifier)>,
    salt_len: usize,
    iteration_count: i32,
    max_iterations: i32,
    parameters: Option<PbmParameter>,
}

impl<'a> PkMacBuilder<'a> {
    pub fn new(digests: &'a dyn DigestProvider, macs: &'a dyn MacProvider) -> Self {
        Self {
            digests,
            macs,
            algorithms: None,
            salt_len: 20,
            iteration_count: 1000,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            parameters: None,
        }
    }

    pub fn with_algorithms(mut self, owf: AlgorithmIdentifier, mac: AlgorithmIdentifier) -> Self {
        self.algorithms = Some((owf, mac));
        self
    }

    pub fn with_salt_length(mut self, length: usize) -> Result<Self, CrmfError> {
        if length < 8 {
            return Err(CrmfError::Invalid("salt length must be at least 8 bytes"));
        }
        self.salt_len = length;
        Ok(self)
    }

    pub fn with_iteration_count(mut self, count: i32) -> Result<Self, CrmfError> {
        if count < 100 {
            return Err(CrmfError::Invalid("iteration count must be at least 100"));
        }
        self.check_iterations(&count.into())?;
        self.iteration_count = count;
        Ok(self)
    }

    pub fn with_max_iterations(mut self, max_iterations: i32) -> Self {
        self.max_iterations = if max_iterations > 0 {
            max_iterations
        } else {
            DEFAULT_MAX_ITERATIONS
        };
        self
    }

    pub fn with_parameters(mut self, parameters: PbmParameter) -> Result<Self, CrmfError> {
        self.check_iterations(parameters.iteration_count())?;
        self.parameters = Some(parameters);
        Ok(self)
    }

    pub fn build(&self, password: &str) -> Result<PkMac<'a>, CrmfError> {
        self.build_with_rng(password, &mut SysRng)
    }

    pub fn build_with_rng(
        &self,
        password: &str,
        rng: &mut (impl TryCryptoRng + ?Sized),
    ) -> Result<PkMac<'a>, CrmfError> {
        if let Some(parameters) = &self.parameters {
            return self.derive(parameters, password);
        }
        self.check_iterations(&self.iteration_count.into())?;
        let mut salt = Vec::new();
        salt.try_reserve_exact(self.salt_len)
            .map_err(|_| CrmfError::Invalid("cannot allocate PKMAC salt"))?;
        salt.resize(self.salt_len, 0);
        rng.try_fill_bytes(&mut salt)
            .map_err(|error| CrmfError::Random(error.to_string()))?;
        let (owf, mac) = match &self.algorithms {
            Some(algorithms) => algorithms.clone(),
            None => (
                AlgorithmIdentifier::new("1.3.14.3.2.26".parse()?),
                AlgorithmIdentifier::with_parameters("1.3.6.1.5.5.8.1.2".parse()?, Asn1Null),
            ),
        };
        self.derive(
            &PbmParameter::new(
                Asn1OctetString::new(&salt),
                owf,
                self.iteration_count.into(),
                mac,
            ),
            password,
        )
    }

    pub fn get(
        &self,
        algorithm: &AlgorithmIdentifier,
        password: &str,
    ) -> Result<PkMac<'a>, CrmfError> {
        if *algorithm.algorithm() != CrmfId::PASSWORD_BASED_MAC.oid() {
            return Err(CrmfError::Invalid("expected passwordBasedMac algorithm"));
        }
        let encoded = algorithm
            .parameters()
            .ok_or(CrmfError::Invalid("missing PBM parameters"))?;
        self.derive(&der::convert(encoded)?, password)
    }

    fn check_iterations(&self, count: &Asn1Integer) -> Result<i32, CrmfError> {
        let count = i32::try_from(count).map_err(|_| CrmfError::IterationCountOutsideInt32)?;
        if count < 1 {
            return Err(CrmfError::IterationCountBelowOne);
        }
        if count > self.max_iterations {
            return Err(CrmfError::IterationCountExceedsLimit {
                count,
                max: self.max_iterations,
            });
        }
        Ok(count)
    }

    fn derive(&self, parameters: &PbmParameter, password: &str) -> Result<PkMac<'a>, CrmfError> {
        let iterations = self.check_iterations(parameters.iteration_count())?;
        let salt = parameters.salt().as_bytes();
        let len = password
            .len()
            .checked_add(salt.len())
            .ok_or(CrmfError::Invalid("PKMAC input too large"))?;
        let mut input = Zeroizing::new(Vec::new());
        input
            .try_reserve_exact(len)
            .map_err(|_| CrmfError::Invalid("cannot allocate PKMAC input"))?;
        input.extend_from_slice(password.as_bytes());
        input.extend_from_slice(salt);

        let mut digest = self.digests.get_by_oid(parameters.owf().algorithm())?;
        digest.try_update(&input)?;
        let mut key = Zeroizing::new(vec![0; digest.digest_size()]);
        digest.try_do_final(&mut key)?;
        drop(input);
        for _ in 1..iterations {
            digest.try_update(&key)?;
            digest.try_do_final(&mut key)?;
        }
        let algorithm = AlgorithmIdentifier::with_parameters(
            CrmfId::PASSWORD_BASED_MAC.oid(),
            der::convert::<tc_asn1::Asn1Object>(parameters)?,
        );
        Ok(PkMac {
            algorithm,
            mac_algorithm: parameters.mac().clone(),
            macs: self.macs,
            key: KeyOwned::new(std::mem::take(&mut *key)),
        })
    }
}

/// A password-based MAC with the derived key retained until drop.
pub struct PkMac<'a> {
    algorithm: AlgorithmIdentifier,
    mac_algorithm: AlgorithmIdentifier,
    macs: &'a dyn MacProvider,
    key: KeyOwned,
}

impl PkMac<'_> {
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    pub fn calculate(&self, input: &[u8]) -> Result<Vec<u8>, CrmfError> {
        Ok(self
            .macs
            .calculate_by_oid(self.mac_algorithm.algorithm(), &self.key, input)?)
    }

    pub fn verify(&self, input: &[u8], tag: &[u8]) -> Result<bool, CrmfError> {
        Ok(self
            .macs
            .verify_by_oid(self.mac_algorithm.algorithm(), &self.key, input, tag)?)
    }
}
