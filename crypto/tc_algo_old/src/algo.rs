use std::sync::OnceLock;

use crate::Policy;
use crate::agreement::{AgreementEntry, AgreementFactory};
use crate::cipher::{CipherEntry, CipherFactory};
use crate::digest::{DigestEntry, DigestFactory};
use crate::generate::key::{KeyGeneratorEntry, KeyGeneratorFactory};
use crate::generate::key_pair::{KeyPairGeneratorEntry, KeyPairGeneratorFactory};
use crate::mac::{MacEntry, MacFactory};
use crate::wrap::{WrapEntry, WrapFactory};
use crate::xof::{XofEntry, XofFactory};

// The instance that the factories are reached through, in place of free functions. It holds what
// they keep between calls; a table that is a constant needs only its filtered list here
#[derive(Clone, Debug, Default)]
pub struct Algo {
    policy: Policy,
    listed_digests: OnceLock<Vec<&'static DigestEntry>>,
    listed_xofs: OnceLock<Vec<&'static XofEntry>>,
    macs: OnceLock<Vec<MacEntry>>,
    listed_macs: OnceLock<Vec<MacEntry>>,
    ciphers: OnceLock<Vec<CipherEntry>>,
    listed_ciphers: OnceLock<Vec<CipherEntry>>,
    listed_key_generators: OnceLock<Vec<&'static KeyGeneratorEntry>>,
    listed_key_pair_generators: OnceLock<Vec<&'static KeyPairGeneratorEntry>>,
    listed_agreements: OnceLock<Vec<&'static AgreementEntry>>,
    listed_wrappers: OnceLock<Vec<&'static WrapEntry>>,
}

impl Algo {
    pub fn new() -> Self {
        Self::default()
    }

    // Replaces the whole policy, which decides what each factory's algorithms lists. Only the
    // filtered lists are made again, not the tables
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
        self.listed_digests = OnceLock::new();
        self.listed_xofs = OnceLock::new();
        self.listed_macs = OnceLock::new();
        self.listed_ciphers = OnceLock::new();
        self.listed_key_generators = OnceLock::new();
        self.listed_key_pair_generators = OnceLock::new();
        self.listed_agreements = OnceLock::new();
        self.listed_wrappers = OnceLock::new();
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn digest(&self) -> DigestFactory<'_> {
        DigestFactory::new(&self.policy, &self.listed_digests)
    }

    pub fn xof(&self) -> XofFactory<'_> {
        XofFactory::new(&self.policy, &self.listed_xofs)
    }

    pub fn mac(&self) -> MacFactory<'_> {
        MacFactory::new(&self.policy, &self.macs, &self.listed_macs)
    }

    pub fn cipher(&self) -> CipherFactory<'_> {
        CipherFactory::new(&self.policy, &self.ciphers, &self.listed_ciphers)
    }

    pub fn key_generator(&self) -> KeyGeneratorFactory<'_> {
        KeyGeneratorFactory::new(&self.policy, &self.listed_key_generators)
    }

    pub fn key_pair_generator(&self) -> KeyPairGeneratorFactory<'_> {
        KeyPairGeneratorFactory::new(&self.policy, &self.listed_key_pair_generators)
    }

    pub fn agreement(&self) -> AgreementFactory<'_> {
        AgreementFactory::new(&self.policy, &self.listed_agreements)
    }

    pub fn wrap(&self) -> WrapFactory<'_> {
        WrapFactory::new(&self.policy, &self.listed_wrappers)
    }
}
