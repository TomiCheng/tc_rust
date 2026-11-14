use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use crate::EntryBase;
use crate::cipher::{Cipher, CipherEntry};

// The source of randomness ISO 10126 padding draws from
pub(super) type Rand = fn() -> Box<dyn CryptoRng>;

// What builds a cipher of one engine in a mode and with a padding, and for CFB and OFB with a
// feedback of that many bits, or of a whole block; block_cipher! writes one
pub(super) type Create = fn(Mode, Padding, Rand, Option<usize>) -> Box<dyn Cipher>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
    // GOST 28147's counter mode, GCTR, which Bouncy Castle calls GOFB: only for a block of 8 bytes
    Gofb,
}

impl Mode {
    const ALL: [Mode; 6] = [
        Mode::Ecb,
        Mode::Cbc,
        Mode::Cfb,
        Mode::Ofb,
        Mode::Ctr,
        Mode::Gofb,
    ];

    // The name first, then the aliases of Bouncy Castle's CipherUtilities, where NONE and a mode
    // left empty are ECB
    fn names(self) -> &'static [&'static str] {
        match self {
            Mode::Ecb => &["ECB", "NONE", ""],
            Mode::Cbc => &["CBC"],
            Mode::Cfb => &["CFB"],
            Mode::Ofb => &["OFB"],
            Mode::Ctr => &["CTR", "SIC"],
            Mode::Gofb => &["GOFB"],
        }
    }

    // The padding Bouncy Castle gives the mode when the name leaves it out, leaves it empty or
    // names RAW: PKCS#7 for the modes of whole blocks, none for the others
    fn default_padding(self) -> Padding {
        match self {
            Mode::Ecb | Mode::Cbc => Padding::Pkcs7,
            Mode::Cfb | Mode::Ofb | Mode::Ctr | Mode::Gofb => Padding::None,
        }
    }

    // ECB and CBC take whole blocks, so they take every padding; the others take a partial last
    // block, so they need none
    fn paddings(self) -> &'static [Padding] {
        match self {
            Mode::Ecb | Mode::Cbc => &Padding::ALL,
            Mode::Cfb | Mode::Ofb | Mode::Ctr | Mode::Gofb => &[Padding::None],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Padding {
    None,
    Pkcs7,
    Iso10126,
    Iso7816d4,
    X923,
    Tbc,
    ZeroByte,
}

impl Padding {
    const ALL: [Padding; 7] = [
        Padding::None,
        Padding::Pkcs7,
        Padding::Iso10126,
        Padding::Iso7816d4,
        Padding::X923,
        Padding::Tbc,
        Padding::ZeroByte,
    ];

    // The name first, then the aliases of Bouncy Castle's CipherUtilities
    fn names(self) -> &'static [&'static str] {
        match self {
            Padding::None => &["NOPADDING"],
            Padding::Pkcs7 => &["PKCS7PADDING", "PKCS7", "PKCS5PADDING", "PKCS5"],
            Padding::Iso10126 => &["ISO10126PADDING", "ISO10126D2PADDING", "ISO10126-2PADDING"],
            Padding::Iso7816d4 => &["ISO7816-4PADDING", "ISO9797-1PADDING"],
            Padding::X923 => &["X923PADDING", "X9.23PADDING"],
            Padding::Tbc => &["TBCPADDING"],
            Padding::ZeroByte => &["ZEROBYTEPADDING"],
        }
    }
}

// Every row of one block cipher: each mode with each padding it takes, named
// `ALGORITHM/MODE/PADDING` after the first of `algorithms`, with every other name of the algorithm,
// the mode and the padding as aliases. The row of a mode's default padding also takes the names
// that leave the padding out, leave it empty or name RAW, as `AES/CBC`, `AES/CBC/` and
// `AES/CBC/RAW`; with ECB, whose name may be empty, that includes `AES/` and `AES` alone, as in
// Bouncy Castle's CipherUtilities. `oids` gives the OIDs of the rows that have them
pub(super) fn block_rows(
    algorithms: &[&'static str],
    create: Create,
    rand: Rand,
    oids: &[(Mode, Padding, &[&str])],
) -> Vec<Box<dyn CipherEntry>> {
    let mut rows: Vec<Box<dyn CipherEntry>> = Vec::new();
    let block_bits = create(Mode::Ecb, Padding::None, rand, None).block_size() * 8;
    for mode in Mode::ALL {
        // GOFB's counter is two words of 32 bits, so it takes a block of 8 bytes only
        if mode == Mode::Gofb && block_bits != 64 {
            continue;
        }
        for &padding in mode.paddings() {
            let mut names = algorithms.iter().flat_map(|algorithm| {
                mode.names().iter().flat_map(move |mode| {
                    padding
                        .names()
                        .iter()
                        .map(move |padding| format!("{algorithm}/{mode}/{padding}"))
                })
            });
            let name = names
                .next()
                .expect("an algorithm, a mode and a padding have a name");
            let mut aliases: Vec<String> = names.collect();
            if padding == mode.default_padding() {
                for algorithm in algorithms {
                    for mode_name in mode.names() {
                        aliases.push(format!("{algorithm}/{mode_name}/RAW"));
                        aliases.push(format!("{algorithm}/{mode_name}/"));
                        aliases.push(format!("{algorithm}/{mode_name}"));
                    }
                    if mode == Mode::Ecb {
                        aliases.push(algorithm.to_string());
                    }
                }
            }
            let oids = oids
                .iter()
                .filter(|(m, p, _)| *m == mode && *p == padding)
                .flat_map(|(_, _, oids)| oids.iter())
                .map(|dotted| dotted.parse().expect("a valid OID"))
                .collect();
            rows.push(Box::new(Row {
                name,
                aliases,
                oids,
                mode,
                padding,
                rand,
                create,
                block_bits,
            }));
        }
    }
    rows
}

struct Row {
    name: String,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    mode: Mode,
    padding: Padding,
    rand: Rand,
    create: Create,
    block_bits: usize,
}

impl Row {
    // The feedback size of a CFB or OFB name, as Bouncy Castle reads `AES/CFB8/NOPADDING`: the
    // digits after the mode, a multiple of 8 from 8 to the bits of a block. Gives the name without
    // them and the size, or None when the name has none or the row is of another mode
    fn feedback_bits(&self, name: &str) -> Option<(String, usize)> {
        let mode = match self.mode {
            Mode::Cfb => "CFB",
            Mode::Ofb => "OFB",
            _ => return None,
        };
        let mut parts: Vec<&str> = name.split('/').collect();
        let segment = parts.get(1)?;
        let digits = segment
            .get(..mode.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(mode))
            .map(|_| &segment[mode.len()..])?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let bits: usize = digits.parse().ok()?;
        if bits == 0 || bits % 8 != 0 || bits > self.block_bits {
            return None;
        }
        parts[1] = mode;
        Some((parts.join("/"), bits))
    }

    fn matches_plain_name(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
            || self
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
    }
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

    // Its names, and for CFB and OFB the same with a feedback size after the mode
    fn matches_name(&self, name: &str) -> bool {
        self.matches_plain_name(name)
            || self
                .feedback_bits(name)
                .is_some_and(|(plain, _)| self.matches_plain_name(&plain))
    }
}

impl CipherEntry for Row {
    // CFB and OFB with a feedback of a whole block
    fn create(&self) -> Box<dyn Cipher> {
        (self.create)(self.mode, self.padding, self.rand, None)
    }

    fn create_by_name(&self, name: &str) -> Box<dyn Cipher> {
        let bits = self
            .feedback_bits(name)
            .filter(|(plain, _)| self.matches_plain_name(plain))
            .map(|(_, bits)| bits);
        (self.create)(self.mode, self.padding, self.rand, bits)
    }
}

// The rows of one padding: `padded!(padding, rand, Ecb, NoOwn, block, EcbBlockCipher::new(engine))`, with
// the engine's block in bytes, puts
// the mode under tc_buffered_cipher with the padding, then in the wrapper of the mode's params,
// which also takes the engine's own params `own`
macro_rules! padded {
    ($padding:expr, $rand:expr, $wrap:path, $own:ty, $block:expr, $mode:expr) => {{
        use tc_block_padding::{
            Iso7816d4Padding, Iso10126Padding, Pkcs7Padding, TbcPadding, X923Padding,
            ZeroBytePadding,
        };
        use tc_buffered_cipher::{BufferedBlockCipher, PaddedBufferedBlockCipher};

        use core::marker::PhantomData;

        use $crate::cipher::algo::block::Padding;
        use $crate::cipher::algo::buffered::Buffered;

        let cipher: Box<dyn $crate::cipher::Cipher> = match $padding {
            Padding::None => Box::new($wrap(Buffered::<_, $own>(
                BufferedBlockCipher::new($mode),
                $block,
                PhantomData,
            ))),
            Padding::Pkcs7 => Box::new($wrap(Buffered::<_, $own>(
                PaddedBufferedBlockCipher::with_padding($mode, Pkcs7Padding::new()),
                $block,
                PhantomData,
            ))),
            Padding::Iso10126 => Box::new($wrap(Buffered::<_, $own>(
                PaddedBufferedBlockCipher::with_padding($mode, Iso10126Padding::new($rand())),
                $block,
                PhantomData,
            ))),
            Padding::Iso7816d4 => Box::new($wrap(Buffered::<_, $own>(
                PaddedBufferedBlockCipher::with_padding($mode, Iso7816d4Padding::new()),
                $block,
                PhantomData,
            ))),
            Padding::X923 => Box::new($wrap(Buffered::<_, $own>(
                PaddedBufferedBlockCipher::with_padding($mode, X923Padding::new()),
                $block,
                PhantomData,
            ))),
            Padding::Tbc => Box::new($wrap(Buffered::<_, $own>(
                PaddedBufferedBlockCipher::with_padding($mode, TbcPadding::new()),
                $block,
                PhantomData,
            ))),
            Padding::ZeroByte => Box::new($wrap(Buffered::<_, $own>(
                PaddedBufferedBlockCipher::with_padding($mode, ZeroBytePadding::new()),
                $block,
                PhantomData,
            ))),
        };
        cipher
    }};
}

// A Create for one engine, as `block_cipher!(DesEngine::new())`: the engine in the mode, under
// tc_buffered_cipher, with the padding. CFB and OFB feed back a whole block.
// `block_cipher!(engine, Own<Rc2ParamsOwned>)` also takes the engine's own params
macro_rules! block_cipher {
    ($engine:expr) => {
        $crate::cipher::algo::block::block_cipher!($engine, $crate::cipher::algo::buffered::NoOwn)
    };
    ($engine:expr, $own:ty) => {
        |mode, padding, rand, feedback_bits| {
            use core::marker::PhantomData;

            use tc_block_cipher::BlockCipher as _;
            use tc_block_modes::{
                CbcBlockCipher, CfbBlockCipher, CtrBlockCipher, EcbBlockCipher, GofbBlockCipher,
                OfbBlockCipher,
            };
            use tc_buffered_cipher::BufferedBlockCipher;

            use $crate::cipher::algo::block::{Mode, padded};
            use $crate::cipher::algo::buffered::{Buffered, Ctr, Ecb};

            let engine = $engine;
            let block = engine.block_size();
            let bits = feedback_bits.unwrap_or(block * 8);
            match mode {
                Mode::Ecb => padded!(padding, rand, Ecb, $own, block, EcbBlockCipher::new(engine)),
                Mode::Cbc => padded!(
                    padding,
                    rand,
                    core::convert::identity,
                    $own,
                    block,
                    CbcBlockCipher::new(engine)
                ),
                Mode::Cfb => Box::new(Buffered::<_, $own>(
                    BufferedBlockCipher::new(CfbBlockCipher::new(engine, bits)),
                    block,
                    PhantomData,
                )),
                Mode::Ofb => Box::new(Buffered::<_, $own>(
                    BufferedBlockCipher::new(OfbBlockCipher::new(engine, bits)),
                    block,
                    PhantomData,
                )),
                Mode::Ctr => Box::new(Ctr(Buffered::<_, $own>(
                    BufferedBlockCipher::new(CtrBlockCipher::new(engine)),
                    block,
                    PhantomData,
                ))),
                Mode::Gofb => Box::new(Buffered::<_, $own>(
                    BufferedBlockCipher::new(GofbBlockCipher::new(engine)),
                    block,
                    PhantomData,
                )),
            }
        }
    };
}

pub(super) use {block_cipher, padded};
