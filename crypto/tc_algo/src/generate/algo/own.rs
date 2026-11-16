use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use super::random::{Rule, random_key};
use crate::generate::{KeyGenerator, KeyGeneratorEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The rows of the keys of the block ciphers with params of their own, RC2, RC5, GOST 28147 and
// Threefish, to give to
// DefaultAlgoBuilder::reg_key_generator: each gives those params, the key with what the cipher
// takes besides it, so that they go straight into its rows. Their names, aliases, OIDs and default
// lengths are those of Bouncy Castle's GeneratorUtilities; init takes a params type of each, and
// without it a row gives the key of the default length with the cipher's defaults
pub(super) fn own(context: &DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>> {
    let rand = context.rand();
    let mut rows: Vec<Box<dyn KeyGeneratorEntry>> = Vec::new();
    let mut add = |name, aliases: &[&'static str], oids: &[&str], kind| {
        rows.push(Box::new(Row {
            name,
            aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            oids: oids
                .iter()
                .map(|dotted| dotted.parse().expect("a valid OID"))
                .collect(),
            kind,
            rand,
        }));
    };
    #[cfg(feature = "rc2")]
    add(
        "RC2",
        &[],
        &["1.2.840.113549.3.2", "1.2.840.113549.1.9.16.3.7"],
        Kind::Rc2,
    );
    #[cfg(feature = "rc5")]
    add("RC5", &["RC5-32"], &[], Kind::Rc5 { key_bytes: 16 });
    #[cfg(feature = "rc5-64")]
    add("RC5-64", &[], &[], Kind::Rc5 { key_bytes: 32 });
    #[cfg(feature = "gost28147")]
    add(
        "GOST28147",
        &["GOST", "GOST-28147"],
        &["1.2.643.2.2.21"],
        Kind::Gost28147,
    );
    #[cfg(feature = "threefish-256")]
    add("THREEFISH-256", &[], &[], Kind::Threefish { key_bytes: 32 });
    #[cfg(feature = "threefish-512")]
    add("THREEFISH-512", &[], &[], Kind::Threefish { key_bytes: 64 });
    #[cfg(feature = "threefish-1024")]
    add(
        "THREEFISH-1024",
        &[],
        &[],
        Kind::Threefish { key_bytes: 128 },
    );
    rows
}

#[derive(Clone, Copy)]
enum Kind {
    #[cfg(feature = "rc2")]
    Rc2,
    #[cfg(any(feature = "rc5", feature = "rc5-64"))]
    Rc5 { key_bytes: usize },
    #[cfg(feature = "gost28147")]
    Gost28147,
    #[cfg(any(
        feature = "threefish-256",
        feature = "threefish-512",
        feature = "threefish-1024"
    ))]
    Threefish { key_bytes: usize },
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    kind: Kind,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KeyGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyGenerator> {
        let rand = (self.rand)();
        match self.kind {
            #[cfg(feature = "rc2")]
            Kind::Rc2 => Box::new(Rc2 {
                params: crate::params::Rc2KeyGenParams::new(16),
                rand,
            }),
            #[cfg(any(feature = "rc5", feature = "rc5-64"))]
            Kind::Rc5 { key_bytes } => Box::new(Rc5 {
                params: crate::params::Rc5KeyGenParams::new(key_bytes),
                rand,
            }),
            #[cfg(feature = "gost28147")]
            Kind::Gost28147 => Box::new(Gost28147 {
                params: crate::params::Gost28147KeyGenParams::new(),
                rand,
            }),
            #[cfg(any(
                feature = "threefish-256",
                feature = "threefish-512",
                feature = "threefish-1024"
            ))]
            Kind::Threefish { key_bytes } => Box::new(Threefish {
                key_bytes,
                params: crate::params::ThreefishKeyGenParams::new(),
                rand,
            }),
        }
    }
}

// An Rc2ParamsOwned: the key, 16 bytes unless set, of 1 to 128 bytes, and an effective key size of
// 1 to 1024 bits, that of the whole key unless set
#[cfg(feature = "rc2")]
struct Rc2 {
    params: crate::params::Rc2KeyGenParams,
    rand: Box<dyn CryptoRng>,
}

#[cfg(feature = "rc2")]
impl KeyGenerator for Rc2 {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<crate::params::Rc2KeyGenParams>()
            .filter(|params| (1..=tc_rc_cipher::RC2_MAX_KEY_BYTES).contains(&params.key_bytes()))
            .filter(|params| {
                params.effective_key_bits().is_none_or(|bits| {
                    (1..=tc_rc_cipher::RC2_MAX_EFFECTIVE_KEY_BITS).contains(&bits)
                })
            })
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.params = *params;
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let key = random_key(self.rand.as_mut(), self.params.key_bytes(), Rule::Random);
        Ok(Box::new(match self.params.effective_key_bits() {
            Some(bits) => crate::params::Rc2ParamsOwned::with_effective_key_bits(key, bits),
            None => crate::params::Rc2ParamsOwned::new(key),
        }))
    }
}

// An Rc5ParamsOwned: the key, of the row's length unless set, of 1 to 255 bytes, and 0 to 255
// rounds, 12 unless set
#[cfg(any(feature = "rc5", feature = "rc5-64"))]
struct Rc5 {
    params: crate::params::Rc5KeyGenParams,
    rand: Box<dyn CryptoRng>,
}

#[cfg(any(feature = "rc5", feature = "rc5-64"))]
impl KeyGenerator for Rc5 {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<crate::params::Rc5KeyGenParams>()
            .filter(|params| (1..=tc_rc_cipher::RC5_MAX_KEY_BYTES).contains(&params.key_bytes()))
            .filter(|params| {
                params
                    .rounds()
                    .is_none_or(|rounds| rounds <= tc_rc_cipher::RC5_MAX_ROUNDS)
            })
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.params = *params;
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let key = random_key(self.rand.as_mut(), self.params.key_bytes(), Rule::Random);
        let rounds = self
            .params
            .rounds()
            .unwrap_or(tc_rc_cipher::RC5_DEFAULT_ROUNDS);
        Ok(Box::new(crate::params::Rc5ParamsOwned::new(key, rounds)))
    }
}

// A Gost28147ParamsOwned: a key of 32 bytes, and the default S-box unless set, of 128 bytes
#[cfg(feature = "gost28147")]
struct Gost28147 {
    params: crate::params::Gost28147KeyGenParams,
    rand: Box<dyn CryptoRng>,
}

#[cfg(feature = "gost28147")]
impl KeyGenerator for Gost28147 {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<crate::params::Gost28147KeyGenParams>()
            .filter(|params| params.s_box().is_none_or(|s_box| s_box.len() == 128))
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.params = params.clone();
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let key = random_key(self.rand.as_mut(), 32, Rule::Random);
        Ok(Box::new(match self.params.s_box() {
            Some(s_box) => crate::params::Gost28147ParamsOwned::with_s_box(key, s_box.to_vec()),
            None => crate::params::Gost28147ParamsOwned::new(key),
        }))
    }
}

// A ThreefishParamsOwned: a key of one block, and a tweak of 16 bytes, zeros unless set
#[cfg(any(
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
struct Threefish {
    key_bytes: usize,
    params: crate::params::ThreefishKeyGenParams,
    rand: Box<dyn CryptoRng>,
}

#[cfg(any(
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
impl KeyGenerator for Threefish {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<crate::params::ThreefishKeyGenParams>()
            .filter(|params| {
                params
                    .tweak()
                    .is_none_or(|tweak| tweak.len() == tc_threefish::TWEAK_BYTES)
            })
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.params = params.clone();
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let key = random_key(self.rand.as_mut(), self.key_bytes, Rule::Random);
        Ok(Box::new(match self.params.tweak() {
            Some(tweak) => crate::params::ThreefishParamsOwned::with_tweak(key, tweak.to_vec()),
            None => crate::params::ThreefishParamsOwned::new(key),
        }))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "gost28147")]
    use tc_gost28147::Gost28147Params;
    #[cfg(feature = "rc2")]
    use tc_rc_cipher::Rc2Params;
    #[cfg(any(feature = "rc5", feature = "rc5-64"))]
    use tc_rc_cipher::Rc5Params;

    use crate::params::KeyParams;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    // Without init, RC2 gives a 16-byte key of 128 effective bits; with init, the key and size set,
    // which encrypt as Rc2ParamsOwned of them does
    #[cfg(feature = "rc2")]
    #[test]
    fn rc2_gives_its_params_of_the_default_or_the_set_size() {
        use crate::params::{ParamsWithIvOwned, Rc2KeyGenParams, Rc2ParamsOwned};

        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        let params = generators.generate_by_name("RC2").unwrap();
        let params = params.as_any().downcast_ref::<Rc2ParamsOwned>().unwrap();
        assert_eq!(params.key().len(), 16);
        assert_eq!(params.effective_key_bits(), 128);

        let params = generators
            .generate_by_name_with("RC2", &Rc2KeyGenParams::new(5))
            .unwrap();
        let params = params.as_any().downcast_ref::<Rc2ParamsOwned>().unwrap();
        assert_eq!((params.key().len(), params.effective_key_bits()), (5, 40));

        let params = generators
            .generate_by_name_with("RC2", &Rc2KeyGenParams::new(16).with_effective_key_bits(64))
            .unwrap();
        let params = params.as_any().downcast_ref::<Rc2ParamsOwned>().unwrap();
        assert_eq!((params.key().len(), params.effective_key_bits()), (16, 64));

        let with_iv = ParamsWithIvOwned::new(
            Rc2ParamsOwned::with_effective_key_bits(params.key().to_vec(), 64),
            vec![0x24; 8],
        );
        let sealed = algo
            .cipher()
            .encrypt_by_name("RC2/CBC/PKCS7PADDING", &with_iv, b"attack at dawn")
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name("RC2/CBC/PKCS7PADDING", &with_iv, &sealed)
            .unwrap();
        assert_eq!(opened, b"attack at dawn");

        for bad in [
            Rc2KeyGenParams::new(0),
            Rc2KeyGenParams::new(129),
            Rc2KeyGenParams::new(16).with_effective_key_bits(0),
            Rc2KeyGenParams::new(16).with_effective_key_bits(1025),
        ] {
            let error = generators.generate_by_name_with("RC2", &bad).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::InvalidParams, "{bad:?}");
        }
    }

    // RC5 and RC5-64 give their params with 12 rounds unless set
    #[cfg(all(feature = "rc5", feature = "rc5-64"))]
    #[test]
    fn rc5_gives_its_params_of_the_default_or_the_set_rounds() {
        use crate::params::{Rc5KeyGenParams, Rc5ParamsOwned};

        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        for (name, bytes) in [("RC5", 16), ("RC5-32", 16), ("RC5-64", 32)] {
            let params = generators.generate_by_name(name).unwrap();
            let params = params.as_any().downcast_ref::<Rc5ParamsOwned>().unwrap();
            assert_eq!((params.key().len(), params.rounds()), (bytes, 12), "{name}");
        }
        let params = generators
            .generate_by_name_with("RC5", &Rc5KeyGenParams::new(8).with_rounds(16))
            .unwrap();
        let params = params.as_any().downcast_ref::<Rc5ParamsOwned>().unwrap();
        assert_eq!((params.key().len(), params.rounds()), (8, 16));

        for bad in [
            Rc5KeyGenParams::new(0),
            Rc5KeyGenParams::new(256),
            Rc5KeyGenParams::new(16).with_rounds(256),
        ] {
            let error = generators.generate_by_name_with("RC5", &bad).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::InvalidParams, "{bad:?}");
        }
    }

    // GOST 28147 gives a 32-byte key with the default S-box unless set
    #[cfg(feature = "gost28147")]
    #[test]
    fn gost28147_gives_its_params_of_the_default_or_the_set_s_box() {
        use crate::params::{Gost28147KeyGenParams, Gost28147ParamsOwned, gost28147_s_box};

        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        let params = generators.generate_by_name("GOST").unwrap();
        let params = params
            .as_any()
            .downcast_ref::<Gost28147ParamsOwned>()
            .unwrap();
        assert_eq!(params.key().len(), 32);

        let s_box = gost28147_s_box::E_A.to_vec();
        let params = generators
            .generate_by_name_with(
                "GOST28147",
                &Gost28147KeyGenParams::new().with_s_box(s_box.clone()),
            )
            .unwrap();
        let params = params
            .as_any()
            .downcast_ref::<Gost28147ParamsOwned>()
            .unwrap();
        assert_eq!(params.s_box(), s_box.as_slice());

        let error = generators
            .generate_by_name_with(
                "GOST28147",
                &Gost28147KeyGenParams::new().with_s_box(vec![0; 64]),
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }

    // Threefish gives a key of its block with a tweak of zeros unless set, which its rows take
    #[cfg(all(
        feature = "threefish-256",
        feature = "threefish-512",
        feature = "threefish-1024"
    ))]
    #[test]
    fn threefish_gives_its_params_of_a_block_and_the_set_tweak() {
        use tc_threefish::ThreefishParams;

        use crate::params::{ThreefishKeyGenParams, ThreefishParamsOwned};

        let algo = DefaultAlgoBuilder::default().build();
        let generators = algo.key_generator();
        for (name, bytes) in [
            ("THREEFISH-256", 32),
            ("THREEFISH-512", 64),
            ("THREEFISH-1024", 128),
        ] {
            let params = generators.generate_by_name(name).unwrap();
            let params = params
                .as_any()
                .downcast_ref::<ThreefishParamsOwned>()
                .unwrap();
            assert_eq!(params.key().len(), bytes, "{name}");
            assert_eq!(params.tweak(), None, "{name}");
        }

        let tweak = vec![0x11; 16];
        let params = generators
            .generate_by_name_with(
                "THREEFISH-256",
                &ThreefishKeyGenParams::new().with_tweak(tweak.clone()),
            )
            .unwrap();
        let sealed = algo
            .cipher()
            .encrypt_by_name("THREEFISH-256/ECB/NOPADDING", params.as_ref(), &[0x33; 32])
            .unwrap();
        let opened = algo
            .cipher()
            .decrypt_by_name("THREEFISH-256/ECB/NOPADDING", params.as_ref(), &sealed)
            .unwrap();
        assert_eq!(opened, [0x33; 32]);
        let params = params
            .as_any()
            .downcast_ref::<ThreefishParamsOwned>()
            .unwrap();
        assert_eq!(params.tweak(), Some(tweak.as_slice()));

        let error = generators
            .generate_by_name_with(
                "THREEFISH-512",
                &ThreefishKeyGenParams::new().with_tweak(vec![0; 8]),
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
