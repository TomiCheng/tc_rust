use core::error::Error;

use tc_asn1::Asn1Oid;
use tc_block_cipher::KeyParams;
use tc_block_modes::{IvParams, KeyWithIvOwned};
use tc_macs::{MacError, MacInit};
use tc_zeroize::Zeroize;

use crate::mac::{Mac, MacEntry};
use crate::params::key::KeyOwned;
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// What a row's MAC takes as an IV
#[allow(dead_code, reason = "a MAC alone uses some of them")]
#[derive(Clone, Copy)]
pub(super) enum Iv {
    // None: a key alone, as CMAC, SipHash, KMAC, Poly1305 and Skein-MAC take
    None,
    // An IV of that many bytes, of zeros when the params have none, as Bouncy Castle's CBC-MAC
    // takes a KeyParameter
    Optional(usize),
    // An IV the params must have, as GMAC and VMPC-MAC take
    Required,
}

// The params a row gives its tc_macs MAC: the key and IV of the row's params, and the own params of
// RC2, RC5, GOST 28147 and Skein that the engine reads through its own trait, with their defaults
// for a bare key
pub(super) struct MacKey {
    key: Vec<u8>,
    iv: Vec<u8>,
    #[allow(dead_code, reason = "read only when RC2 is on")]
    rc2_bits: Option<usize>,
    #[allow(dead_code, reason = "read only when RC5 is on")]
    rc5_rounds: Option<usize>,
    #[allow(dead_code, reason = "read only when GOST 28147 is on")]
    s_box: Option<Vec<u8>>,
}

impl MacKey {
    pub(super) fn new(params: &dyn Params, iv: Iv) -> Result<Self, AlgoError> {
        let mut key = MacKey {
            key: Vec::new(),
            iv: Vec::new(),
            rc2_bits: None,
            rc5_rounds: None,
            s_box: None,
        };
        let given = key
            .read(params.as_any())
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        match (iv, given) {
            (Iv::None, None) => {}
            (Iv::Optional(length), None) => key.iv = vec![0; length],
            (Iv::Optional(_) | Iv::Required, Some(given)) => key.iv = given.to_vec(),
            (Iv::None, Some(_)) | (Iv::Required, None) => {
                return Err(AlgoError::new(ErrorKind::InvalidParams));
            }
        }
        Ok(key)
    }

    // Takes the key and the own params, and gives the IV of the params, if any; None for params of
    // another type
    fn read<'a>(&mut self, params: &'a dyn core::any::Any) -> Option<Option<&'a [u8]>> {
        if let Some(params) = params.downcast_ref::<KeyOwned>() {
            self.key = params.key().to_vec();
            return Some(None);
        }
        if let Some(params) = params.downcast_ref::<KeyWithIvOwned>() {
            self.key = KeyParams::key(params).to_vec();
            return Some(Some(IvParams::iv(params)));
        }
        #[cfg(feature = "rc-cipher")]
        {
            use tc_block_modes::ParamsWithIvOwned;
            use tc_rc_cipher::{Rc2Params, Rc2ParamsOwned};

            let mut rc2 = |own: &Rc2ParamsOwned| {
                self.key = own.key().to_vec();
                self.rc2_bits = Some(own.effective_key_bits());
            };
            if let Some(params) = params.downcast_ref::<Rc2ParamsOwned>() {
                rc2(params);
                return Some(None);
            }
            if let Some(params) = params.downcast_ref::<ParamsWithIvOwned<Rc2ParamsOwned>>() {
                rc2(params.params());
                return Some(Some(params.iv()));
            }
        }
        #[cfg(feature = "rc-cipher")]
        {
            use tc_block_modes::ParamsWithIvOwned;
            use tc_rc_cipher::{Rc5Params, Rc5ParamsOwned};

            let mut rc5 = |own: &Rc5ParamsOwned| {
                self.key = own.key().to_vec();
                self.rc5_rounds = Some(own.rounds());
            };
            if let Some(params) = params.downcast_ref::<Rc5ParamsOwned>() {
                rc5(params);
                return Some(None);
            }
            if let Some(params) = params.downcast_ref::<ParamsWithIvOwned<Rc5ParamsOwned>>() {
                rc5(params.params());
                return Some(Some(params.iv()));
            }
        }
        #[cfg(feature = "gost28147")]
        {
            use tc_block_modes::ParamsWithIvOwned;
            use tc_gost28147::{Gost28147Params, Gost28147ParamsOwned};

            let mut gost = |own: &Gost28147ParamsOwned| {
                self.key = own.key().to_vec();
                self.s_box = Some(own.s_box().to_vec());
            };
            if let Some(params) = params.downcast_ref::<Gost28147ParamsOwned>() {
                gost(params);
                return Some(None);
            }
            if let Some(params) = params.downcast_ref::<ParamsWithIvOwned<Gost28147ParamsOwned>>() {
                gost(params.params());
                return Some(Some(params.iv()));
            }
        }
        None
    }
}

impl Drop for MacKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.s_box.zeroize();
    }
}

impl KeyParams for MacKey {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl IvParams for MacKey {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

// A bare key has the effective size of tc_rc_cipher's default, as Bouncy Castle's RC2 takes a
// KeyParameter
#[cfg(feature = "rc-cipher")]
impl tc_rc_cipher::Rc2Params for MacKey {
    fn effective_key_bits(&self) -> usize {
        self.rc2_bits.unwrap_or_else(|| {
            tc_rc_cipher::Rc2Params::effective_key_bits(&tc_rc_cipher::Rc2ParamsRef::new(&self.key))
        })
    }
}

// A bare key has 12 rounds, as Bouncy Castle's RC5 takes a KeyParameter
#[cfg(feature = "rc-cipher")]
impl tc_rc_cipher::Rc5Params for MacKey {
    fn rounds(&self) -> usize {
        self.rc5_rounds.unwrap_or(tc_rc_cipher::RC5_DEFAULT_ROUNDS)
    }
}

// A bare key has the default S-box
#[cfg(feature = "gost28147")]
impl tc_gost28147::Gost28147Params for MacKey {
    fn s_box(&self) -> &[u8] {
        self.s_box
            .as_deref()
            .unwrap_or(&tc_gost28147::s_box::DEFAULT)
    }
}

#[cfg(feature = "skein-mac")]
impl tc_skein_mac::SkeinParams for MacKey {
    fn key(&self) -> Option<&[u8]> {
        Some(&self.key)
    }
}

// A tc_macs MAC under the Mac of tc_algo: its params come as dyn Params, and its errors as
// AlgoError
pub(super) struct RowMac<M> {
    mac: M,
    iv: Iv,
}

impl<M> RowMac<M> {
    pub(super) fn new(mac: M, iv: Iv) -> Self {
        Self { mac, iv }
    }
}

impl<M, E> tc_macs::Mac for RowMac<M>
where
    M: tc_macs::Mac<Error = MacError<E>>,
    E: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn mac_size(&self) -> usize {
        self.mac.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.mac.update(input).map_err(mac_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.mac.do_final(output).map_err(mac_error)
    }

    fn reset(&mut self) {
        self.mac.reset();
    }
}

impl<M> MacInit<dyn Params> for RowMac<M>
where
    M: MacInit<MacKey>,
    M::Error: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let key = MacKey::new(params, self.iv)?;
        self.mac
            .init(&key)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

impl<M, E> Mac for RowMac<M>
where
    M: tc_macs::Mac<Error = MacError<E>> + MacInit<MacKey>,
    E: Error + Send + Sync + 'static,
    <M as MacInit<MacKey>>::Error: Error + Send + Sync + 'static,
{
}

pub(super) fn mac_error<E: Error + Send + Sync + 'static>(error: MacError<E>) -> AlgoError {
    let kind = match error {
        MacError::NotInitialised => ErrorKind::NotInitialized,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

pub(super) type Create = Box<dyn Fn() -> Box<dyn Mac> + Send + Sync>;

// A row by its name, aliases and OIDs
pub(super) struct Row {
    name: String,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    create: Create,
}

pub(super) fn row(
    name: String,
    aliases: Vec<String>,
    oids: &[&str],
    create: Create,
) -> Box<dyn MacEntry> {
    let oids = oids
        .iter()
        .map(|dotted| dotted.parse().expect("a valid OID"))
        .collect();
    Box::new(Row {
        name,
        aliases,
        oids,
        create,
    })
}

// A row of fixed names
#[allow(dead_code, reason = "unused by the block cipher MACs")]
pub(super) fn named(
    name: &str,
    aliases: &[&str],
    oids: &[&str],
    create: fn() -> Box<dyn Mac>,
) -> Box<dyn MacEntry> {
    row(
        name.to_string(),
        aliases.iter().map(|alias| alias.to_string()).collect(),
        oids,
        Box::new(create),
    )
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        &self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl MacEntry for Row {
    fn create(&self) -> Box<dyn Mac> {
        (self.create)()
    }
}
