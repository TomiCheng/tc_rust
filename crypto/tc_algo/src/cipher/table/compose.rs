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

use super::specs::{AlgorithmSpec, ModeKind, PaddingKind};
use crate::cipher::CipherEntry;
use crate::cipher::classify::Classify;
use crate::cipher::dyn_cipher::{DynCipher, Mapped};
use crate::cipher::entry::Kind;
use crate::cipher::init_params::SymmetricParams;

pub(super) fn boxed<T>(cipher: T) -> Box<dyn DynCipher>
where
    T: BufferedCipher + BufferedCipherInit<SymmetricParams> + Send + 'static,
    <T as BufferedCipher>::Error: Classify + core::error::Error + Send + Sync + 'static,
    <T as BufferedCipherInit<SymmetricParams>>::Error:
        Classify + core::error::Error + Send + Sync + 'static,
{
    Box::new(Mapped::<T, SymmetricParams>::new(cipher))
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

pub(in crate::cipher) fn create(entry: &CipherEntry) -> Box<dyn DynCipher> {
    match entry.kind() {
        Kind::Block {
            algorithm,
            mode,
            padding,
        } => block(algorithm, mode.kind, padding.kind),
        Kind::Stream { algorithm } => (algorithm.create)(),
        #[cfg(feature = "rsa")]
        Kind::Asymmetric {
            algorithm, padding, ..
        } => (algorithm.create)(padding.kind),
    }
}

// Builds a block cipher layer by layer: engine, mode, then padding and buffering
fn block(algorithm: &AlgorithmSpec, mode: ModeKind, padding: PaddingKind) -> Box<dyn DynCipher> {
    let engine = algorithm.engine;
    let feedback_bits = algorithm.block_size * 8;
    match mode {
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
