use std::sync::Arc;

use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};

use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::crl::X509Crl;
use crate::default_x509_operator::{DefaultX509Operator, Parsers};
use crate::operator::parser::{self, DefaultParserProvider, ParserEntry};
use crate::operator::signer::{self, SignerEntry};
use crate::operator::spki::{self, DefaultSpkiProvider, SpkiEntry};
use crate::{DefaultX509OperatorContext, X509Operator, X509OperatorBuilder};

#[derive(Clone)]
pub struct DefaultX509OperatorBuilder {
    algo: Option<Arc<dyn Algo>>,
    spkis: Vec<spki::CreateRows>,
    signers: Vec<signer::CreateRows>,
    certificate_parsers: Vec<parser::CreateRows<X509Certificate>>,
    crl_parsers: Vec<parser::CreateRows<X509Crl>>,
    attribute_certificate_parsers: Vec<parser::CreateRows<X509AttributeCertificate>>,
}

// Starts with the built-in rows
impl Default for DefaultX509OperatorBuilder {
    fn default() -> Self {
        Self {
            algo: None,
            spkis: spki::BUILT_IN.to_vec(),
            signers: signer::BUILT_IN.to_vec(),
            certificate_parsers: parser::CERTIFICATE_BUILT_IN.to_vec(),
            crl_parsers: parser::CRL_BUILT_IN.to_vec(),
            attribute_certificate_parsers: parser::ATTRIBUTE_CERTIFICATE_BUILT_IN.to_vec(),
        }
    }
}

impl DefaultX509OperatorBuilder {
    // The algorithms to work with. Without this, build uses DefaultAlgoBuilder's defaults
    pub fn set_algo(&mut self, algo: impl Into<Arc<dyn Algo>>) {
        self.algo = Some(algo.into());
    }

    // Rows registered later are tried first, so they can take over a built-in one
    pub fn reg_spki(&mut self, create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SpkiEntry>>) {
        self.spkis.push(create);
    }

    // Rows registered later are found first, so they can take over a built-in one
    pub fn reg_signer(
        &mut self,
        create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SignerEntry>>,
    ) {
        self.signers.push(create);
    }

    // Parsers of certificates registered later are found first, so they can take over a built-in
    // one of the same name
    pub fn reg_certificate_parser(
        &mut self,
        create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn ParserEntry<X509Certificate>>>,
    ) {
        self.certificate_parsers.push(create);
    }

    // As reg_certificate_parser, for CRLs
    pub fn reg_crl_parser(
        &mut self,
        create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn ParserEntry<X509Crl>>>,
    ) {
        self.crl_parsers.push(create);
    }

    // As reg_certificate_parser, for attribute certificates
    pub fn reg_attribute_certificate_parser(
        &mut self,
        create: fn(&DefaultX509OperatorContext) -> Vec<Box<dyn ParserEntry<X509AttributeCertificate>>>,
    ) {
        self.attribute_certificate_parsers.push(create);
    }
}

// The rows of every create, the last registered first
fn parser_rows<T>(
    creates: &[parser::CreateRows<T>],
    context: &DefaultX509OperatorContext,
) -> DefaultParserProvider<T> {
    DefaultParserProvider::new(
        creates
            .iter()
            .rev()
            .flat_map(|create| create(context))
            .collect(),
    )
}

impl X509OperatorBuilder for DefaultX509OperatorBuilder {
    fn build(&self) -> Box<dyn X509Operator> {
        let algo = self
            .algo
            .clone()
            .unwrap_or_else(|| DefaultAlgoBuilder::default().build().into());
        let context = DefaultX509OperatorContext;
        let spki_rows = self
            .spkis
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .collect();
        let signer_rows = self
            .signers
            .iter()
            .rev()
            .flat_map(|create| create(&context))
            .map(Arc::from)
            .collect();
        Box::new(DefaultX509Operator::new(
            algo,
            DefaultSpkiProvider::new(spki_rows),
            signer_rows,
            Parsers {
                certificate: parser_rows(&self.certificate_parsers, &context),
                crl: parser_rows(&self.crl_parsers, &context),
                attribute_certificate: parser_rows(&self.attribute_certificate_parsers, &context),
            },
        ))
    }
}
