// The MACs over a block cipher, each row appearing when both the MAC's feature and the cipher's are
// on. The names, the aliases and what each row builds follow Bouncy Castle's MacUtilities
#![allow(
    dead_code,
    reason = "the helpers go unused when no block cipher feature is on"
)]

#[cfg(all(feature = "cbc-mac", feature = "desede"))]
use tc_asn1::NamedOid;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, InitError};

use super::names;
use crate::mac::MacEntry;
use crate::mac::dyn_mac::Mapped;
use crate::mac::init_params::MacParams;
use crate::need::Need;

// What the MACs need of a block cipher; every engine of the table has these errors
trait Engine:
    BlockCipher<Error = BlockError>
    + for<'a> BlockCipherInit<MacParams<'a>, Error = InitError>
    + Send
    + 'static
{
}

impl<T> Engine for T where
    T: BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<MacParams<'a>, Error = InitError>
        + Send
        + 'static
{
}

// CMAC's IV is always zero, so it takes none
#[cfg(feature = "cmac")]
fn cmac<C: Engine>(row: &[&str], engine: fn() -> C) -> MacEntry {
    MacEntry::new(names(row), &[], Need::Forbidden, move || {
        Box::new(Mapped::key_only(tc_macs::Cmac::new(engine())))
    })
}

// GCM's nonce is the IV, which a MAC here must be given and must never repeat under one key
#[cfg(feature = "gmac")]
fn gmac<C: Engine>(row: &[&str], engine: fn() -> C) -> MacEntry {
    MacEntry::new(names(row), &[], Need::Required, move || {
        Box::new(Mapped::key_only(tc_macs::Gmac::new(engine())))
    })
}

// A tag of half a block, as Bouncy Castle's CbcBlockCipherMac has by default
#[cfg(feature = "cbc-mac")]
fn cbc<C: Engine>(row: &[&str], engine: fn() -> C) -> MacEntry {
    let block = engine().block_size();
    MacEntry::new(names(row), &[], Need::Optional, move || {
        Box::new(Mapped::new(tc_macs::CbcMac::new(engine()), block))
    })
}

// A tag of the whole block
#[cfg(feature = "cbc-mac")]
fn cbc_full<C: Engine>(row: &[&str], engine: fn() -> C) -> MacEntry {
    let block = engine().block_size();
    MacEntry::new(names(row), &[], Need::Optional, move || {
        Box::new(Mapped::new(
            tc_macs::CbcMac::with_mac_size(engine(), block),
            block,
        ))
    })
}

// A tag of the whole block, over the message padded as ISO 7816-4 says
#[cfg(feature = "cbc-mac")]
fn cbc_full_iso7816<C: Engine>(row: &[&str], engine: fn() -> C) -> MacEntry {
    let block = engine().block_size();
    MacEntry::new(names(row), &[], Need::Optional, move || {
        Box::new(Mapped::new(
            tc_macs::PaddedCbcMac::with_mac_size(
                engine(),
                block,
                tc_block_padding::Iso7816d4Padding::new(),
            ),
            block,
        ))
    })
}

// 8-bit feedback and a tag of half a block, as Bouncy Castle's CfbBlockCipherMac has by default
#[cfg(feature = "cfb-mac")]
fn cfb<C: Engine>(row: &[&str], engine: fn() -> C) -> MacEntry {
    let block = engine().block_size();
    MacEntry::new(names(row), &[], Need::Optional, move || {
        Box::new(Mapped::new(tc_macs::CfbMac::new(engine()), block))
    })
}

// DESEDEMAC also goes by the OID of DESede in CBC mode, as in Bouncy Castle
#[cfg(all(feature = "cbc-mac", feature = "desede"))]
const DES_EDE3_CBC: &[NamedOid] = &[NamedOid::new(
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07],
    "1.2.840.113549.3.7",
    "des-ede3-cbc",
)];

pub(super) fn rows() -> Vec<MacEntry> {
    vec![
        #[cfg(all(feature = "cmac", feature = "aes"))]
        cmac(&["AESCMAC"], tc_aes::AesEngine::new),
        #[cfg(all(feature = "gmac", feature = "aes"))]
        gmac(&["AES-GMAC"], tc_aes::AesEngine::new),
        #[cfg(all(feature = "cbc-mac", feature = "des"))]
        cbc(&["DESMAC", "DES"], tc_des::DesEngine::new),
        #[cfg(all(feature = "cfb-mac", feature = "des"))]
        cfb(&["DESMAC/CFB8", "DES/CFB8"], tc_des::DesEngine::new),
        #[cfg(all(feature = "cbc-mac", feature = "des"))]
        cbc_full(&["DESMAC64", "DES64"], tc_des::DesEngine::new),
        #[cfg(all(feature = "cmac", feature = "desede"))]
        cmac(&["DESEDECMAC"], tc_des::DesEdeEngine::new),
        #[cfg(all(feature = "cbc-mac", feature = "desede"))]
        MacEntry::new(
            names(&["DESEDEMAC", "DESEDE"]),
            DES_EDE3_CBC,
            Need::Optional,
            || {
                Box::new(Mapped::new(
                    tc_macs::CbcMac::new(tc_des::DesEdeEngine::new()),
                    8,
                ))
            },
        ),
        #[cfg(all(feature = "cfb-mac", feature = "desede"))]
        cfb(
            &["DESEDEMAC/CFB8", "DESEDE/CFB8"],
            tc_des::DesEdeEngine::new,
        ),
        #[cfg(all(feature = "cbc-mac", feature = "desede"))]
        cbc_full(&["DESEDEMAC64", "DESEDE64"], tc_des::DesEdeEngine::new),
        #[cfg(all(feature = "cbc-mac", feature = "desede"))]
        cbc_full_iso7816(
            &[
                "DESEDEMAC64WITHISO7816-4PADDING",
                "DESEDE64WITHISO7816-4PADDING",
                "DESEDEISO9797ALG1MACWITHISO7816-4PADDING",
                "DESEDEISO9797ALG1WITHISO7816-4PADDING",
            ],
            tc_des::DesEdeEngine::new,
        ),
        #[cfg(all(feature = "cbc-mac", feature = "skipjack"))]
        cbc(
            &["SKIPJACKMAC", "SKIPJACK"],
            tc_misc_block_cipher::skipjack::SkipjackEngine::new,
        ),
        #[cfg(all(feature = "cfb-mac", feature = "skipjack"))]
        cfb(
            &["SKIPJACKMAC/CFB8", "SKIPJACK/CFB8"],
            tc_misc_block_cipher::skipjack::SkipjackEngine::new,
        ),
        #[cfg(all(feature = "cbc-mac", feature = "idea"))]
        cbc(
            &["IDEAMAC", "IDEA"],
            tc_misc_block_cipher::idea::IdeaEngine::new,
        ),
        #[cfg(all(feature = "cfb-mac", feature = "idea"))]
        cfb(
            &["IDEAMAC/CFB8", "IDEA/CFB8"],
            tc_misc_block_cipher::idea::IdeaEngine::new,
        ),
        #[cfg(all(feature = "cbc-mac", feature = "rc2"))]
        cbc(&["RC2MAC", "RC2"], tc_rc_cipher::Rc2Engine::new),
        #[cfg(all(feature = "cfb-mac", feature = "rc2"))]
        cfb(&["RC2MAC/CFB8", "RC2/CFB8"], tc_rc_cipher::Rc2Engine::new),
        #[cfg(all(feature = "cbc-mac", feature = "rc5"))]
        cbc(&["RC5MAC", "RC5"], tc_rc_cipher::Rc532Engine::new),
        #[cfg(all(feature = "cfb-mac", feature = "rc5"))]
        cfb(&["RC5MAC/CFB8", "RC5/CFB8"], tc_rc_cipher::Rc532Engine::new),
    ]
}
