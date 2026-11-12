use tc_asn1::Asn1Oid;

use crate::digest::{Digest, DigestEntry};
use crate::{AlgoError, EntryBase, ErrorKind};

// A row over a digest of tc_digest, with the names and OIDs given
pub(super) fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    create: fn() -> Box<dyn Digest>,
) -> Vec<Box<dyn DigestEntry>> {
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
    create: fn() -> Box<dyn Digest>,
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

impl DigestEntry for Entry {
    fn create(&self) -> Box<dyn Digest> {
        (self.create)()
    }
}

pub(super) struct TcDigest<D>(pub(super) D);

impl<D: tc_digest::Digest> Digest for TcDigest<D> {
    fn digest_size(&self) -> usize {
        self.0.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    // tc_digest panics on a short output, so the length is checked here first
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        if output.len() < self.digest_size() {
            return Err(AlgoError::new(ErrorKind::DataLength));
        }
        Ok(self.0.do_final(output))
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}
