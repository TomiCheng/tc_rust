use std::sync::Arc;

use tc_kdf::sp800_108::{
    KdfCounter, KdfCounterParamsOwned, KdfDoublePipeline, KdfDoublePipelineParamsOwned,
    KdfFeedback, KdfFeedbackParamsOwned,
};
use tc_macs::{KeyParams, KeyRef, MacInit};

use super::typed::{Row, Typed};
use crate::kdf::KdfEntry;
use crate::mac::{Mac, MacEntry};
use crate::params::KeyOwned;
use crate::{AlgoError, DefaultAlgoContext};

// The rows of the SP 800-108 KDFs, to give to DefaultAlgoBuilder::reg_kdf: the counter, feedback
// and double-pipeline modes, each over every HMAC and CMAC row that is on, the PRFs SP 800-108
// names. A row is named after its mode and MAC, KDF-COUNTER-HMAC-SHA256 or KDF-FEEDBACK-AESCMAC,
// and goes by the MAC's other names too. Bouncy Castle has no factory of KDFs, so the names are
// this crate's own
pub(super) fn sp800_108(context: &DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>> {
    let mut rows = Vec::new();
    let macs = crate::mac::BUILT_IN
        .iter()
        .flat_map(|create| create(context))
        .filter(|mac| {
            mac.name().starts_with("HMAC-")
                || mac.aliases().iter().any(|alias| alias.ends_with("-CMAC"))
        })
        .map(Arc::<dyn MacEntry>::from);
    for mac in macs {
        let others: Vec<&str> = mac.aliases().iter().map(String::as_str).collect();

        let entry = mac.clone();
        rows.push(Row::boxed(
            "KDF-COUNTER",
            mac.name(),
            &others,
            Vec::new(),
            move || Typed::<_, KdfCounterParamsOwned>::boxed(KdfCounter::new(RowMac::new(&entry))),
        ));
        let entry = mac.clone();
        rows.push(Row::boxed(
            "KDF-FEEDBACK",
            mac.name(),
            &others,
            Vec::new(),
            move || {
                Typed::<_, KdfFeedbackParamsOwned>::boxed(KdfFeedback::new(RowMac::new(&entry)))
            },
        ));
        let entry = mac.clone();
        rows.push(Row::boxed(
            "KDF-DOUBLEPIPELINE",
            mac.name(),
            &others,
            Vec::new(),
            move || {
                Typed::<_, KdfDoublePipelineParamsOwned>::boxed(KdfDoublePipeline::new(
                    RowMac::new(&entry),
                ))
            },
        ));
    }
    rows
}

// A MAC row as the PRF that tc_kdf keys with a KeyRef: the key goes to the row as a KeyOwned
struct RowMac(Box<dyn Mac>);

impl RowMac {
    fn new(entry: &Arc<dyn MacEntry>) -> Self {
        Self(entry.create())
    }
}

impl tc_macs::Mac for RowMac {
    type Error = AlgoError;

    fn mac_size(&self) -> usize {
        self.0.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.0.update(input)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl MacInit<KeyRef<'_>> for RowMac {
    type Error = AlgoError;

    fn init(&mut self, params: &KeyRef<'_>) -> Result<(), AlgoError> {
        self.0.init(&KeyOwned::new(params.key().to_vec()))
    }
}

#[cfg(all(
    test,
    feature = "hmac",
    feature = "sha256",
    feature = "cmac",
    feature = "aes"
))]
mod tests {
    use tc_kdf::sp800_108::{
        KdfCounterParamsRef, KdfDoublePipelineParamsRef, KdfFeedbackParamsRef,
    };
    use tc_kdf::{Kdf as _, KdfInit as _};
    use tc_macs::Hmac;
    use tc_sha::Sha256Digest;

    use super::*;
    use crate::params::KeyLength;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, ErrorKind, Params};

    const KI: [u8; 16] = [0x3c; 16];
    const IV: [u8; 32] = [0x77; 32];
    const FIXED: [u8; 9] = *b"label\0ctx";

    fn row(name: &str, params: &dyn Params) -> Vec<u8> {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name(name).unwrap();
        kdf.init(params).unwrap();
        let mut output = vec![0; 70];
        kdf.generate_bytes(&mut output).unwrap();
        output
    }

    // The same mode over HMAC-SHA256 itself, outside the factory
    macro_rules! direct {
        ($kdf:expr, $params:expr) => {{
            let mut kdf = $kdf;
            kdf.init(&$params).unwrap();
            let mut output = vec![0; 70];
            kdf.generate_bytes(&mut output).unwrap();
            output
        }};
    }

    fn hmac() -> Hmac<Sha256Digest> {
        Hmac::new(Sha256Digest::new())
    }

    #[test]
    fn each_mode_over_hmac_gives_what_tc_kdf_gives() {
        assert_eq!(
            row(
                "KDF-COUNTER-HMAC-SHA256",
                &KdfCounterParamsOwned::new(KI.to_vec(), FIXED.to_vec(), 32)
            ),
            direct!(
                KdfCounter::new(hmac()),
                KdfCounterParamsRef::new(&KI, &FIXED, 32)
            )
        );
        assert_eq!(
            row(
                "KDF-FEEDBACK-HMAC-SHA256",
                &KdfFeedbackParamsOwned::with_counter(KI.to_vec(), IV.to_vec(), FIXED.to_vec(), 8)
            ),
            direct!(
                KdfFeedback::new(hmac()),
                KdfFeedbackParamsRef::with_counter(&KI, &IV, &FIXED, 8)
            )
        );
        assert_eq!(
            row(
                "KDF-DOUBLEPIPELINE-HMAC-SHA256",
                &KdfDoublePipelineParamsOwned::without_counter(KI.to_vec(), FIXED.to_vec())
            ),
            direct!(
                KdfDoublePipeline::new(hmac()),
                KdfDoublePipelineParamsRef::without_counter(&KI, &FIXED)
            )
        );
    }

    #[test]
    fn cmac_is_a_prf_and_the_mac_aliases_find_the_rows() {
        let params = KdfCounterParamsOwned::new(KI.to_vec(), FIXED.to_vec(), 16);
        let cmac = row("KDF-COUNTER-AESCMAC", &params);
        assert_eq!(cmac, row("kdf-counter-aes-cmac", &params));
        let hmac = row("KDF-COUNTER-HMAC-SHA256", &params);
        assert_ne!(cmac, hmac);
        assert_eq!(hmac, row("KDF-COUNTER-HMAC/SHA-256", &params));
    }

    #[test]
    fn a_bad_counter_length_or_other_params_are_invalid_and_generating_needs_an_init() {
        let algo = DefaultAlgoBuilder::default().build();
        let mut kdf = algo.kdf().get_by_name("KDF-COUNTER-HMAC-SHA256").unwrap();
        let error = kdf.generate_bytes(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotInitialized);
        let error = kdf
            .init(&KdfCounterParamsOwned::new(KI.to_vec(), FIXED.to_vec(), 12))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let error = kdf.init(&KeyLength::new(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
