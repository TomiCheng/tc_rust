#![allow(
    dead_code,
    unused_macros,
    reason = "a MAC feature on without its ciphers has no rows"
)]

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, InitError};

use super::row::{Iv, MacKey, RowMac, row};
use crate::DefaultAlgoContext;
use crate::mac::{Mac, MacEntry};

// An engine a block cipher MAC takes: keyed by MacKey, through KeyParams or its own params trait
pub(super) trait Engine:
    BlockCipher<Error = BlockError> + BlockCipherInit<MacKey, Error = InitError> + Send + 'static
{
}

impl<E> Engine for E where
    E: BlockCipher<Error = BlockError>
        + BlockCipherInit<MacKey, Error = InitError>
        + Send
        + 'static
{
}

// The block cipher MACs of Bouncy Castle's MacUtilities: CBC-MAC and CFB-MAC of 8 bits, both with a
// tag of half a block, over DES, DESede, Skipjack, IDEA, RC2 and RC5, and CMAC over AES and DESede.
// Further, CMAC over every block cipher of 8 or 16 bytes, and GMAC over every one of 16
pub(super) fn block(_context: &DefaultAlgoContext) -> Vec<Box<dyn MacEntry>> {
    #[allow(unused_mut, reason = "empty when no cipher is on")]
    let mut rows: Vec<Box<dyn MacEntry>> = Vec::new();

    #[cfg(feature = "des")]
    {
        use tc_des::DesEngine;
        #[cfg(feature = "cbc-mac")]
        {
            rows.push(cbc("DESMAC", &["DES"], &[], DesEngine::new, None));
            rows.push(cbc("DESMAC64", &["DES64"], &[], DesEngine::new, Some(8)));
        }
        #[cfg(feature = "cfb-mac")]
        rows.push(cfb("DESMAC/CFB8", &["DES/CFB8"], DesEngine::new));
        #[cfg(feature = "cmac")]
        rows.push(cmac("DES", DesEngine::new));
    }
    #[cfg(feature = "desede")]
    {
        use tc_des::DesEdeEngine;
        #[cfg(feature = "cbc-mac")]
        {
            rows.push(cbc(
                "DESEDEMAC",
                &["DESEDE"],
                &["1.2.840.113549.3.7"],
                DesEdeEngine::new,
                None,
            ));
            rows.push(cbc(
                "DESEDEMAC64",
                &["DESEDE64"],
                &[],
                DesEdeEngine::new,
                Some(8),
            ));
            rows.push(super::row::named(
                "DESEDEMAC64WITHISO7816-4PADDING",
                &[
                    "DESEDE64WITHISO7816-4PADDING",
                    "DESEDEISO9797ALG1MACWITHISO7816-4PADDING",
                    "DESEDEISO9797ALG1WITHISO7816-4PADDING",
                ],
                &[],
                || {
                    Box::new(RowMac::new(
                        tc_macs::PaddedCbcMac::with_mac_size(
                            DesEdeEngine::new(),
                            8,
                            tc_block_padding::Iso7816d4Padding::new(),
                        ),
                        Iv::Optional(8),
                    ))
                },
            ));
        }
        #[cfg(feature = "cfb-mac")]
        rows.push(cfb("DESEDEMAC/CFB8", &["DESEDE/CFB8"], DesEdeEngine::new));
        #[cfg(feature = "cmac")]
        rows.push(cmac("DESEDE", DesEdeEngine::new));
    }
    #[cfg(feature = "skipjack")]
    {
        use tc_misc_block_cipher::skipjack::SkipjackEngine;
        #[cfg(feature = "cbc-mac")]
        rows.push(cbc(
            "SKIPJACKMAC",
            &["SKIPJACK"],
            &[],
            SkipjackEngine::new,
            None,
        ));
        #[cfg(feature = "cfb-mac")]
        rows.push(cfb(
            "SKIPJACKMAC/CFB8",
            &["SKIPJACK/CFB8"],
            SkipjackEngine::new,
        ));
        #[cfg(feature = "cmac")]
        rows.push(cmac("SKIPJACK", SkipjackEngine::new));
    }
    #[cfg(feature = "idea")]
    {
        use tc_misc_block_cipher::idea::IdeaEngine;
        #[cfg(feature = "cbc-mac")]
        rows.push(cbc("IDEAMAC", &["IDEA"], &[], IdeaEngine::new, None));
        #[cfg(feature = "cfb-mac")]
        rows.push(cfb("IDEAMAC/CFB8", &["IDEA/CFB8"], IdeaEngine::new));
        #[cfg(feature = "cmac")]
        rows.push(cmac("IDEA", IdeaEngine::new));
    }
    #[cfg(feature = "rc2")]
    {
        use tc_rc_cipher::Rc2Engine;
        #[cfg(feature = "cbc-mac")]
        rows.push(cbc("RC2MAC", &["RC2"], &[], Rc2Engine::new, None));
        #[cfg(feature = "cfb-mac")]
        rows.push(cfb("RC2MAC/CFB8", &["RC2/CFB8"], Rc2Engine::new));
        #[cfg(feature = "cmac")]
        rows.push(cmac("RC2", Rc2Engine::new));
    }
    #[cfg(feature = "rc5")]
    {
        use tc_rc_cipher::Rc532Engine;
        #[cfg(feature = "cbc-mac")]
        rows.push(cbc("RC5MAC", &["RC5"], &[], Rc532Engine::new, None));
        #[cfg(feature = "cfb-mac")]
        rows.push(cfb("RC5MAC/CFB8", &["RC5/CFB8"], Rc532Engine::new));
        #[cfg(feature = "cmac")]
        rows.push(cmac("RC5", Rc532Engine::new));
    }

    // CMAC over the other ciphers of 8 bytes
    #[cfg(feature = "cmac")]
    {
        #[cfg(feature = "blowfish")]
        rows.push(cmac("BLOWFISH", tc_blowfish::BlowfishEngine::new));
        #[cfg(feature = "cast5")]
        rows.push(cmac("CAST5", tc_cast::Cast5Engine::new));
        #[cfg(feature = "tea")]
        rows.push(cmac("TEA", tc_misc_block_cipher::tea::TeaEngine::new));
        #[cfg(feature = "xtea")]
        rows.push(cmac("XTEA", tc_misc_block_cipher::tea::XteaEngine::new));
        #[cfg(feature = "gost28147")]
        rows.push(cmac("GOST28147", tc_gost28147::Gost28147Engine::new));
    }

    // CMAC and GMAC over the ciphers of 16 bytes
    macro_rules! wide {
        ($name:literal, $engine:path) => {{
            #[cfg(feature = "cmac")]
            rows.push(cmac($name, $engine));
            #[cfg(feature = "gmac")]
            rows.push(gmac($name, $engine));
        }};
    }
    #[cfg(feature = "aes")]
    wide!("AES", tc_aes::AesEngine::new);
    #[cfg(feature = "aria")]
    wide!("ARIA", tc_aria::AriaEngine::new);
    #[cfg(feature = "camellia")]
    wide!("CAMELLIA", tc_camellia::CamelliaEngine::new);
    #[cfg(feature = "sm4")]
    wide!("SM4", tc_sm4::Sm4Engine::new);
    #[cfg(feature = "seed")]
    wide!("SEED", tc_seed::SeedEngine::new);
    #[cfg(feature = "twofish")]
    wide!("TWOFISH", tc_twofish::TwofishEngine::new);
    #[cfg(feature = "serpent")]
    wide!("SERPENT", tc_serpent::SerpentEngine::new);
    #[cfg(feature = "tnepres")]
    wide!("TNEPRES", tc_serpent::TnepresEngine::new);
    #[cfg(feature = "cast6")]
    wide!("CAST6", tc_cast::Cast6Engine::new);
    #[cfg(feature = "noekeon")]
    wide!("NOEKEON", tc_misc_block_cipher::noekeon::NoekeonEngine::new);
    #[cfg(feature = "rc6")]
    wide!("RC6", tc_rc_cipher::Rc6Engine::new);
    #[cfg(feature = "rc5-64")]
    wide!("RC5-64", tc_rc_cipher::Rc564Engine::new);

    rows
}

// CBC-MAC, with a tag of half a block or of mac_size bytes; a zero IV unless the params have one
#[cfg(feature = "cbc-mac")]
fn cbc<E: Engine>(
    name: &str,
    aliases: &[&str],
    oids: &[&str],
    engine: fn() -> E,
    mac_size: Option<usize>,
) -> Box<dyn MacEntry> {
    row(
        name.to_string(),
        aliases.iter().map(|alias| alias.to_string()).collect(),
        oids,
        Box::new(move || -> Box<dyn Mac> {
            let engine = engine();
            let block = engine.block_size();
            let mac = match mac_size {
                Some(mac_size) => tc_macs::CbcMac::with_mac_size(engine, mac_size),
                None => tc_macs::CbcMac::new(engine),
            };
            Box::new(RowMac::new(mac, Iv::Optional(block)))
        }),
    )
}

// CFB-MAC of 8 bits, with a tag of half a block; a zero IV unless the params have one
#[cfg(feature = "cfb-mac")]
fn cfb<E: Engine>(name: &str, aliases: &[&str], engine: fn() -> E) -> Box<dyn MacEntry> {
    row(
        name.to_string(),
        aliases.iter().map(|alias| alias.to_string()).collect(),
        &[],
        Box::new(move || -> Box<dyn Mac> {
            let engine = engine();
            let block = engine.block_size();
            Box::new(RowMac::new(
                tc_macs::CfbMac::new(engine),
                Iv::Optional(block),
            ))
        }),
    )
}

// CMAC with a tag of a block, named AESCMAC as in Bouncy Castle, or AES-CMAC; a key alone
#[cfg(feature = "cmac")]
fn cmac<E: Engine>(cipher: &str, engine: fn() -> E) -> Box<dyn MacEntry> {
    row(
        format!("{cipher}CMAC"),
        vec![format!("{cipher}-CMAC")],
        &[],
        Box::new(move || -> Box<dyn Mac> {
            Box::new(RowMac::new(tc_macs::Cmac::new(engine()), Iv::None))
        }),
    )
}

// GMAC with a tag of 16 bytes, named AESGMAC as CMAC is, or AES-GMAC as in Bouncy Castle's
// provider; a key and an IV
#[cfg(feature = "gmac")]
fn gmac<E: Engine>(cipher: &str, engine: fn() -> E) -> Box<dyn MacEntry> {
    row(
        format!("{cipher}GMAC"),
        vec![format!("{cipher}-GMAC")],
        &[],
        Box::new(move || -> Box<dyn Mac> {
            Box::new(RowMac::new(tc_macs::Gmac::new(engine()), Iv::Required))
        }),
    )
}

#[cfg(all(
    test,
    feature = "cbc-mac",
    feature = "cfb-mac",
    feature = "des",
    feature = "desede"
))]
mod tests {
    use crate::params::{KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    const KEY: &str = "0123456789abcdef";
    const IV: &str = "1234567890abcdef";
    const INPUT: &str = "37363534333231204e6f77206973207468652074696d6520666f7220";

    // Bouncy Castle's MacTest
    #[test]
    fn des_cbc_and_cfb_macs_give_the_tags_of_bouncy_castle() {
        let algo = DefaultAlgoBuilder::default().build();
        let macs = algo.mac();
        let key = KeyOwned::new(unhex(KEY));
        let with_iv = KeyWithIvOwned::new(unhex(KEY), unhex(IV));
        let input = unhex(INPUT);

        let tag = macs.calculate_by_name("DESMac", &key, &input).unwrap();
        assert_eq!(hex(&tag), "f1d30f68");
        let tag = macs.calculate_by_name("DES", &with_iv, &input).unwrap();
        assert_eq!(hex(&tag), "58d2e77e");
        let tag = macs
            .calculate_by_name("DESMac/CFB8", &with_iv, &input)
            .unwrap();
        assert_eq!(hex(&tag), "cd647403");
    }

    #[test]
    fn the_desede_macs_of_eight_bytes_give_the_tags_of_bouncy_castle() {
        let algo = DefaultAlgoBuilder::default().build();
        let macs = algo.mac();
        let key = KeyOwned::new(unhex("7CA110454A1A6E570131D9619DC1376E"));

        let tag = macs
            .calculate_by_name("DESEDE64", &key, b"Hello World !!!!")
            .unwrap();
        assert_eq!(hex(&tag), "862304d33af01096");

        let tag = macs
            .calculate_by_name("DESedeMac64withISO7816-4Padding", &key, &unhex(INPUT))
            .unwrap();
        assert_eq!(tag.len(), 8);
        for alias in [
            "DESEDE64WITHISO7816-4PADDING",
            "DESEDEISO9797ALG1MACWITHISO7816-4PADDING",
            "DESEDEISO9797ALG1WITHISO7816-4PADDING",
        ] {
            assert_eq!(
                macs.calculate_by_name(alias, &key, &unhex(INPUT)).unwrap(),
                tag
            );
        }
    }

    #[test]
    fn an_iv_that_is_not_a_block_is_refused() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut mac = algo.mac().get_by_name("DESMAC").unwrap();
        let error = mac
            .init(&KeyWithIvOwned::new(unhex(KEY), vec![0; 7]))
            .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidParams);
    }
}

#[cfg(all(test, feature = "cmac", feature = "gmac", feature = "aes"))]
mod aes_tests {
    use crate::params::{KeyOwned, KeyWithIvOwned};
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind};

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // RFC 4493, example 2
    #[test]
    fn aes_cmac_gives_the_tag_of_rfc_4493() {
        let algo = DefaultAlgoBuilder::default().build();
        let key = KeyOwned::new(unhex("2b7e151628aed2a6abf7158809cf4f3c"));
        let message = unhex("6bc1bee22e409f96e93d7e117393172a");
        for name in ["AESCMAC", "AES-CMAC"] {
            let tag = algo.mac().calculate_by_name(name, &key, &message).unwrap();
            assert_eq!(hex(&tag), "070a16b46b4d4144f79bdd9dd04a287c");
        }
    }

    // GCM's test case 1 of McGrew and Viega: no plaintext and no AAD, so GMAC of an empty message
    #[test]
    fn aes_gmac_gives_the_tag_of_gcm_test_case_1() {
        let algo = DefaultAlgoBuilder::default().build();
        let params = KeyWithIvOwned::new(vec![0; 16], vec![0; 12]);
        let tag = algo
            .mac()
            .calculate_by_name("AES-GMAC", &params, &[])
            .unwrap();
        assert_eq!(hex(&tag), "58e2fccefa7e3061367f1d57a4e7455a");
    }

    #[test]
    fn cmac_refuses_an_iv_and_gmac_needs_one() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut cmac = algo.mac().get_by_name("AESCMAC").unwrap();
        let error = cmac
            .init(&KeyWithIvOwned::new(vec![0; 16], vec![0; 16]))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);

        let mut gmac = algo.mac().get_by_name("AESGMAC").unwrap();
        let error = gmac.init(&KeyOwned::new(vec![0; 16])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
