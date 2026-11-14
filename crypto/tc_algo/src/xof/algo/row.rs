use tc_asn1::Asn1Oid;
use tc_digest::{TryDigest, TryXof};

use crate::digest::Digest;
use crate::xof::{Xof, XofEntry};
use crate::{AlgoError, EntryBase, ErrorKind};

// A row over an XOF of tc_digest, with the names and OIDs given
pub(super) fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    create: fn() -> Box<dyn Xof>,
) -> Vec<Box<dyn XofEntry>> {
    vec![Box::new(Entry {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids
            .iter()
            .map(|oid| oid.parse().expect("a valid OID"))
            .collect(),
        create,
    })]
}

struct Entry {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    create: fn() -> Box<dyn Xof>,
}

impl EntryBase for Entry {
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

impl XofEntry for Entry {
    fn create(&self) -> Box<dyn Xof> {
        (self.create)()
    }
}

// An XOF with nothing to set, so init keeps the default that refuses any params
pub(super) struct TcXof<D>(pub(super) D);

impl<D: tc_digest::Xof> TryDigest for TcXof<D> {
    type Error = AlgoError;

    fn digest_size(&self) -> usize {
        self.0.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.0.update(input);
        Ok(())
    }

    // tc_digest panics on a short output, so the length is checked here first
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        if output.len() < self.digest_size() {
            return Err(AlgoError::new(ErrorKind::DataLength));
        }
        Ok(self.0.do_final(output))
    }

    fn try_reset(&mut self) -> Result<(), AlgoError> {
        self.0.reset();
        Ok(())
    }
}

impl<D: tc_digest::Xof> TryXof for TcXof<D> {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        Ok(self.0.output(output))
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        Ok(self.0.output_final(output))
    }
}

impl<D: tc_digest::Xof> Digest for TcXof<D> {}

impl<D: tc_digest::Xof> Xof for TcXof<D> {}
