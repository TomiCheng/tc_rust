use crate::default_algo_asn1::DefaultAlgoAsn1;
use crate::spki::{self, DefaultSpkiProvider, SpkiEntry};
use crate::{AlgoAsn1, AlgoAsn1Builder, DefaultAlgoAsn1Context};

#[derive(Clone)]
pub struct DefaultAlgoAsn1Builder {
    spkis: Vec<spki::CreateRows>,
}

// 從內建的列開始
impl Default for DefaultAlgoAsn1Builder {
    fn default() -> Self {
        Self {
            spkis: spki::BUILT_IN.to_vec(),
        }
    }
}

impl DefaultAlgoAsn1Builder {
    // 後註冊的列先試，可以取代內建的
    pub fn reg_spki(&mut self, create: fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>>) {
        self.spkis.push(create);
    }
}

impl AlgoAsn1Builder for DefaultAlgoAsn1Builder {
    fn build(&self) -> Box<dyn AlgoAsn1> {
        let context = DefaultAlgoAsn1Context;
        let spki_rows = self
            .spkis
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        Box::new(DefaultAlgoAsn1::new(DefaultSpkiProvider::new(spki_rows)))
    }
}
