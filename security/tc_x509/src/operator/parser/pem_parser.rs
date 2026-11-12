use std::io::{self, BufRead, Read};

use tc_asn1::Asn1Error;
use tc_pem::PemReader;

use super::{Parser, ParserEntry};
use crate::X509Error;
use crate::cert::{X509AttributeCertificate, X509Certificate};
use crate::crl::X509Crl;

// Decodes the content of one PEM block
pub(super) type Decode<T> = fn(&[u8]) -> Result<T, Asn1Error>;

// A BufRead that holds one octet at most, so that reading a PEM block takes nothing past it
pub(super) struct OneOctet<'a> {
    inner: &'a mut dyn Read,
    octet: [u8; 1],
    held: bool,
}

impl<'a> OneOctet<'a> {
    pub(super) fn new(inner: &'a mut dyn Read) -> Self {
        Self {
            inner,
            octet: [0],
            held: false,
        }
    }
}

impl Read for OneOctet<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let read = available.len().min(buf.len());
        buf[..read].copy_from_slice(&available[..read]);
        self.consume(read);
        Ok(read)
    }
}

impl BufRead for OneOctet<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if !self.held {
            loop {
                match self.inner.read(&mut self.octet) {
                    Ok(0) => return Ok(&[]),
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            self.held = true;
        }
        Ok(&self.octet)
    }

    fn consume(&mut self, amount: usize) {
        if amount > 0 {
            self.held = false;
        }
    }
}

// The "PEM" format: PEM blocks one after another, those whose label is one of the type's taken
// in order and the others passed over, as BC's PemParser does. It reads a block an octet at a
// time and nothing past it, so a file is best read through a BufReader
pub(crate) struct PemParser<T> {
    labels: &'static [&'static str],
    decode: Decode<T>,
}

impl<T> Parser<T> for PemParser<T> {
    fn parse(&mut self, input: &mut dyn Read) -> Result<Option<T>, X509Error> {
        let mut reader = PemReader::new(OneOctet::new(input));
        while let Some(object) = reader.read_pem_object()? {
            if self.labels.contains(&object.pem_type()) {
                return Ok(Some((self.decode)(object.content())?));
            }
        }
        Ok(None)
    }
}

pub(crate) struct PemParserEntry<T> {
    pub(super) labels: &'static [&'static str],
    pub(super) decode: Decode<T>,
}

impl PemParserEntry<X509Certificate> {
    pub(crate) fn certificates() -> Self {
        Self {
            labels: &["CERTIFICATE", "X509 CERTIFICATE"],
            decode: X509Certificate::decode,
        }
    }
}

impl PemParserEntry<X509Crl> {
    pub(crate) fn crls() -> Self {
        Self {
            labels: &["X509 CRL", "CRL"],
            decode: X509Crl::decode,
        }
    }
}

impl PemParserEntry<X509AttributeCertificate> {
    pub(crate) fn attribute_certificates() -> Self {
        Self {
            labels: &["ATTRIBUTE CERTIFICATE"],
            decode: X509AttributeCertificate::decode,
        }
    }
}

impl<T: 'static> ParserEntry<T> for PemParserEntry<T> {
    fn name(&self) -> &str {
        "PEM"
    }

    fn create(&self) -> Box<dyn Parser<T>> {
        Box::new(PemParser {
            labels: self.labels,
            decode: self.decode,
        })
    }
}
