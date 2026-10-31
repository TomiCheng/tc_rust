use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use tc_aead_cipher::{CcmBlockCipher, EaxBlockCipher, GcmBlockCipher, OcbBlockCipher};
use tc_block_modes::{
    CbcBlockCipher, CfbBlockCipher, CtrBlockCipher, EcbBlockCipher, OfbBlockCipher,
};
use tc_block_padding::{
    Iso7816d4Padding, Iso10126Padding, Pkcs7Padding, TbcPadding, X923Padding, ZeroBytePadding,
};
use tc_buffered_cipher::{
    BufferedAeadBlockCipher, BufferedBlockCipher, BufferedCipher, BufferedCipherInit,
    PaddedBufferedBlockCipher,
};

use super::specs::{ModeKind, PaddingKind};
use crate::cipher::CipherEntry;
use crate::cipher::classify::Classify;
use crate::cipher::dyn_cipher::{DynCipher, Mapped};
use crate::cipher::init_params::InitParams;

fn boxed<T>(cipher: T) -> Box<dyn DynCipher>
where
    T: BufferedCipher + BufferedCipherInit<InitParams> + Send + 'static,
    <T as BufferedCipher>::Error: Classify + core::error::Error + Send + Sync + 'static,
    <T as BufferedCipherInit<InitParams>>::Error:
        Classify + core::error::Error + Send + Sync + 'static,
{
    Box::new(Mapped(cipher))
}

// A mode with the padding layer on top; a macro, so each concrete type is checked on its own
macro_rules! padded {
    ($mode:expr, $padding:expr) => {
        match $padding {
            PaddingKind::NoPadding => boxed(BufferedBlockCipher::new($mode)),
            PaddingKind::Pkcs7 => boxed(PaddedBufferedBlockCipher::with_padding(
                $mode,
                Pkcs7Padding::new(),
            )),
            PaddingKind::Iso10126 => boxed(PaddedBufferedBlockCipher::with_padding(
                $mode,
                Iso10126Padding::new(UnwrapErr(SysRng)),
            )),
            PaddingKind::Iso7816 => boxed(PaddedBufferedBlockCipher::with_padding(
                $mode,
                Iso7816d4Padding::new(),
            )),
            PaddingKind::X923 => boxed(PaddedBufferedBlockCipher::with_padding(
                $mode,
                X923Padding::new(),
            )),
            PaddingKind::Tbc => boxed(PaddedBufferedBlockCipher::with_padding(
                $mode,
                TbcPadding::new(),
            )),
            PaddingKind::ZeroByte => boxed(PaddedBufferedBlockCipher::with_padding(
                $mode,
                ZeroBytePadding::new(),
            )),
        }
    };
}

// Builds the entry's cipher layer by layer: engine, mode, then padding and buffering
pub(in crate::cipher) fn create(entry: &CipherEntry) -> Box<dyn DynCipher> {
    let algorithm = entry.algorithm();
    let engine = algorithm.engine;
    let feedback_bits = algorithm.block_size * 8;
    let padding = entry.padding().kind;
    match entry.mode().kind {
        ModeKind::Ecb => padded!(EcbBlockCipher::new(engine()), padding),
        ModeKind::Cbc => padded!(CbcBlockCipher::new(engine()), padding),
        ModeKind::Cfb => padded!(CfbBlockCipher::new(engine(), feedback_bits), padding),
        ModeKind::Ofb => padded!(OfbBlockCipher::new(engine(), feedback_bits), padding),
        ModeKind::Ctr => padded!(CtrBlockCipher::new(engine()), padding),
        ModeKind::Ccm => boxed(BufferedAeadBlockCipher::new(CcmBlockCipher::new(engine()))),
        ModeKind::Eax => boxed(BufferedAeadBlockCipher::new(EaxBlockCipher::new(engine()))),
        ModeKind::Gcm => boxed(BufferedAeadBlockCipher::new(GcmBlockCipher::new(engine()))),
        ModeKind::Ocb => boxed(BufferedAeadBlockCipher::new(OcbBlockCipher::new(
            engine(),
            engine(),
        ))),
    }
}
