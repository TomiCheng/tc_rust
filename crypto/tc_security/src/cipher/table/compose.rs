use tc_aead_cipher::{CcmBlockCipher, EaxBlockCipher, GcmBlockCipher, OcbBlockCipher};
use tc_block_modes::{
    CbcBlockCipher, CfbBlockCipher, CtrBlockCipher, EcbBlockCipher, OfbBlockCipher,
};
use tc_block_padding::{
    Iso7816d4Padding, Iso10126Padding, Pkcs7Padding, TbcPadding, X923Padding, ZeroBytePadding,
};
use tc_buffered_cipher::{BufferedAeadBlockCipher, BufferedBlockCipher, PaddedBufferedBlockCipher};

use super::{algorithm_spec, standalone_spec};
use crate::cipher::any_mode::AnyMode;
use crate::cipher::{Algorithm, AnyCipher, Mode, Padding};

/// 沒有模式的 cipher 直接建立；block cipher 依三個 enum 當場組出：引擎 → 模式 → padding 與緩衝層。
pub(in crate::cipher) fn create_cipher(
    algorithm: Algorithm,
    mode: Option<Mode>,
    padding: Option<Padding>,
) -> AnyCipher {
    if let Some(standalone) = standalone_spec(algorithm) {
        return (standalone.cipher)();
    }
    let (Some(mode), Some(padding)) = (mode, padding) else {
        unreachable!("block cipher entries always have a mode and a padding");
    };
    let engine = algorithm_spec(algorithm).engine;
    let feedback_bits = algorithm_spec(algorithm).block_size * 8;
    match mode {
        Mode::Ecb => padded(AnyMode::new(EcbBlockCipher::new(engine())), padding),
        Mode::Cbc => padded(AnyMode::new(CbcBlockCipher::new(engine())), padding),
        Mode::Cfb => padded(
            AnyMode::new(CfbBlockCipher::new(engine(), feedback_bits)),
            padding,
        ),
        Mode::Ofb => padded(
            AnyMode::new(OfbBlockCipher::new(engine(), feedback_bits)),
            padding,
        ),
        Mode::Ctr => padded(AnyMode::new(CtrBlockCipher::new(engine())), padding),
        Mode::Ccm => AnyCipher::new(BufferedAeadBlockCipher::new(CcmBlockCipher::new(engine()))),
        Mode::Eax => AnyCipher::new(BufferedAeadBlockCipher::new(EaxBlockCipher::new(engine()))),
        Mode::Gcm => AnyCipher::new(BufferedAeadBlockCipher::new(GcmBlockCipher::new(engine()))),
        Mode::Ocb => AnyCipher::new(BufferedAeadBlockCipher::new(OcbBlockCipher::new(
            engine(),
            engine(),
        ))),
    }
}

fn padded(mode: AnyMode, padding: Padding) -> AnyCipher {
    match padding {
        Padding::NoPadding => AnyCipher::new(BufferedBlockCipher::new(mode)),
        Padding::Pkcs7 => AnyCipher::new(PaddedBufferedBlockCipher::with_padding(
            mode,
            Pkcs7Padding::new(),
        )),
        Padding::Iso10126 => AnyCipher::new(PaddedBufferedBlockCipher::with_padding(
            mode,
            Iso10126Padding::new(rand::rng()),
        )),
        Padding::Iso7816 => AnyCipher::new(PaddedBufferedBlockCipher::with_padding(
            mode,
            Iso7816d4Padding::new(),
        )),
        Padding::X923 => AnyCipher::new(PaddedBufferedBlockCipher::with_padding(
            mode,
            X923Padding::new(),
        )),
        Padding::Tbc => AnyCipher::new(PaddedBufferedBlockCipher::with_padding(
            mode,
            TbcPadding::new(),
        )),
        Padding::ZeroByte => AnyCipher::new(PaddedBufferedBlockCipher::with_padding(
            mode,
            ZeroBytePadding::new(),
        )),
    }
}
