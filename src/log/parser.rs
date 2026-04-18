// SPDX-License-Identifier: Apache-2.0

//! Binary IMA event-log parser.
//!
//! Wire format (one record):
//!
//! ```text
//! +----------------------------------------------------------+
//! | u32  PCR Index                                           |
//! | [N]byte Template Data Hash      (N = template_hash_size) |
//! | u32  Template Name Length                                |
//! | [L]byte Template Name           (not NUL-terminated)     |
//! | u32  Template Data Length       (ABSENT for "ima")       |
//! | [D]byte Template Data                                    |
//! +----------------------------------------------------------+
//! ```
//!
//! Integers are host-endian by default. When the kernel was booted with
//! `ima_canonical_fmt` they are little-endian; use
//! [`ParseOptions::with_endianness`] to match.

use std::io::Read;

use crate::error::{Error, Result};
use crate::hash::HashAlgorithm;

use super::event::Event;
use super::template::{
    Digest, ImaBufEntry, ImaEntry, ImaNgEntry, ImaSigEntry, TemplateData, TemplateField,
};
use super::{
    IMA_BUF_TEMPLATE_NAME, IMA_EVENT_NAME_LEN_MAX, IMA_NG_TEMPLATE_NAME, IMA_SIG_TEMPLATE_NAME,
    IMA_TEMPLATE_NAME,
};

/// Byte order of the integer fields in the binary log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endianness {
    /// Little-endian. What you get from `ima_canonical_fmt` and from every
    /// little-endian host (virtually everything today).
    #[default]
    Little,
    /// Big-endian. Host-native on big-endian machines that did not set the
    /// canonical flag.
    Big,
    /// Whatever byte order the host running the parser uses.
    Native,
}

impl Endianness {
    fn u32_from(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
            Self::Native => u32::from_ne_bytes(bytes),
        }
    }
}

/// Tunables for the binary parser.
#[derive(Debug, Clone)]
pub struct ParseOptions {
    endianness: Endianness,
    template_hash_algorithm: HashAlgorithm,
    max_field_len: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            template_hash_algorithm: HashAlgorithm::Sha1,
            max_field_len: 16 * 1024 * 1024,
        }
    }
}

impl ParseOptions {
    /// Override the byte order used to decode 32-bit length/count fields.
    #[must_use]
    pub fn with_endianness(mut self, endianness: Endianness) -> Self {
        self.endianness = endianness;
        self
    }

    /// Override the hash algorithm used to size the fixed-width
    /// `template_hash` field. The kernel writes one binary log per
    /// configured PCR bank, so this will typically match the suffix of the
    /// securityfs file you're parsing.
    #[must_use]
    pub fn with_template_hash_algorithm(mut self, algo: HashAlgorithm) -> Self {
        self.template_hash_algorithm = algo;
        self
    }

    /// Cap on the size of any variable-length field the parser will try to
    /// allocate. Default is 16 MiB, which comfortably accommodates every
    /// real-world buffer but prevents a corrupted log from triggering a
    /// pathological allocation.
    #[must_use]
    pub fn with_max_field_len(mut self, max: usize) -> Self {
        self.max_field_len = max;
        self
    }

    /// Returns the configured endianness.
    #[must_use]
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the configured template hash algorithm.
    #[must_use]
    pub fn template_hash_algorithm(&self) -> HashAlgorithm {
        self.template_hash_algorithm
    }
}

/// Streaming parser that yields one [`Event`] per `next()` call.
///
/// The parser reads lazily from a [`Read`]er, so it is safe to point at an
/// enormous measurement list without buffering all of it in memory.
pub struct EventLogParser<R: Read> {
    reader: R,
    opts: ParseOptions,
    eof: bool,
}

impl<R: Read> EventLogParser<R> {
    /// Construct a parser over `reader` with the given options.
    pub fn new(reader: R, opts: ParseOptions) -> Self {
        Self {
            reader,
            opts,
            eof: false,
        }
    }

    /// Access the options this parser was constructed with.
    #[must_use]
    pub fn options(&self) -> &ParseOptions {
        &self.opts
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<bool> {
        // Returns Ok(true) on success, Ok(false) on clean EOF at the first
        // byte, or an error when EOF happens mid-record.
        let mut filled = 0;
        while filled < buf.len() {
            match self.reader.read(&mut buf[filled..])? {
                0 => {
                    if filled == 0 {
                        return Ok(false);
                    }
                    return Err(Error::UnexpectedEof {
                        expected: buf.len() - filled,
                        context: "record body",
                    });
                }
                n => filled += n,
            }
        }
        Ok(true)
    }

    fn read_u32(&mut self, context: &'static str) -> Result<Option<u32>> {
        let mut buf = [0u8; 4];
        let mut filled = 0;
        while filled < 4 {
            match self.reader.read(&mut buf[filled..])? {
                0 => {
                    if filled == 0 {
                        return Ok(None);
                    }
                    return Err(Error::UnexpectedEof {
                        expected: 4 - filled,
                        context,
                    });
                }
                n => filled += n,
            }
        }
        Ok(Some(self.opts.endianness.u32_from(buf)))
    }

    fn read_vec(&mut self, len: usize, context: &'static str) -> Result<Vec<u8>> {
        if len > self.opts.max_field_len {
            return Err(Error::InvalidLength {
                value: len as u64,
                limit: self.opts.max_field_len as u64,
                context,
            });
        }
        let mut buf = vec![0u8; len];
        if !self.read_exact(&mut buf)? {
            return Err(Error::UnexpectedEof {
                expected: len,
                context,
            });
        }
        Ok(buf)
    }

    fn read_event(&mut self) -> Result<Option<Event>> {
        // 1) PCR index – also serves as our EOF probe.
        let pcr_index = match self.read_u32("PCR index")? {
            Some(v) => v,
            None => return Ok(None),
        };

        // 2) Template hash – fixed-width, no length prefix.
        let hash_size = self.opts.template_hash_algorithm.digest_size();
        let template_hash = self.read_vec(hash_size, "template hash")?;

        // 3) Template name.
        let name_len = self
            .read_u32("template name length")?
            .ok_or(Error::UnexpectedEof {
                expected: 4,
                context: "template name length",
            })? as usize;
        let name_bytes = self.read_vec(name_len, "template name")?;
        let template_name = String::from_utf8(name_bytes).map_err(|_| Error::InvalidUtf8 {
            context: "template name",
        })?;

        // 4) Template data length (suppressed for the legacy "ima" template).
        let (template_data_raw, template_data) = if template_name == IMA_TEMPLATE_NAME {
            // Legacy `ima` template: 20-byte digest + 256-byte padded name.
            let raw = self.read_vec(20 + IMA_EVENT_NAME_LEN_MAX + 1, "ima template data")?;
            let entry = decode_legacy_ima(&raw)?;
            (raw, TemplateData::Ima(entry))
        } else {
            let data_len = self
                .read_u32("template data length")?
                .ok_or(Error::UnexpectedEof {
                    expected: 4,
                    context: "template data length",
                })? as usize;
            let raw = self.read_vec(data_len, "template data")?;
            let decoded = decode_generic(&template_name, &raw)?;
            (raw, decoded)
        };

        Ok(Some(Event {
            pcr_index,
            template_hash,
            template_name,
            template_data,
            template_data_raw,
        }))
    }
}

impl<R: Read> Iterator for EventLogParser<R> {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.eof {
            return None;
        }
        match self.read_event() {
            Ok(Some(ev)) => Some(Ok(ev)),
            Ok(None) => {
                self.eof = true;
                None
            }
            Err(e) => {
                self.eof = true;
                Some(Err(e))
            }
        }
    }
}

// ---------------------------------------------------------------------
// Template decoders
// ---------------------------------------------------------------------

fn decode_legacy_ima(raw: &[u8]) -> Result<ImaEntry> {
    if raw.len() != 20 + IMA_EVENT_NAME_LEN_MAX + 1 {
        return Err(Error::InvalidLength {
            value: raw.len() as u64,
            limit: (20 + IMA_EVENT_NAME_LEN_MAX + 1) as u64,
            context: "legacy ima template data",
        });
    }
    let mut digest = [0u8; 20];
    digest.copy_from_slice(&raw[..20]);

    let name_slice = &raw[20..];
    let end = name_slice
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(name_slice.len());
    let filename = std::str::from_utf8(&name_slice[..end])
        .map_err(|_| Error::InvalidUtf8 {
            context: "legacy ima filename",
        })?
        .to_owned();

    Ok(ImaEntry { digest, filename })
}

fn decode_generic(template_name: &str, raw: &[u8]) -> Result<TemplateData> {
    let fields = split_fields(raw)?;
    let decoded = match template_name {
        n if n == IMA_NG_TEMPLATE_NAME => decode_ima_ng(&fields)?,
        n if n == IMA_SIG_TEMPLATE_NAME => decode_ima_sig(&fields)?,
        n if n == IMA_BUF_TEMPLATE_NAME => decode_ima_buf(&fields)?,
        _ => TemplateData::Unknown(
            fields
                .into_iter()
                .map(|data| TemplateField { data })
                .collect(),
        ),
    };
    Ok(decoded)
}

/// Decode the framed `template_data` into a plain list of field payloads.
///
/// Each field is `<u32 LE length> || <bytes>`. We always use little-endian
/// for these inner lengths – that's what the kernel writes, regardless of
/// `ima_canonical_fmt`, because the template-hash computation code uses
/// exactly those bytes.
fn split_fields(raw: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut fields = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if i + 4 > raw.len() {
            return Err(Error::UnexpectedEof {
                expected: 4,
                context: "template field length",
            });
        }
        let len = u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]) as usize;
        i += 4;
        let end = i.checked_add(len).ok_or(Error::InvalidLength {
            value: len as u64,
            limit: raw.len() as u64,
            context: "template field",
        })?;
        if end > raw.len() {
            return Err(Error::UnexpectedEof {
                expected: end - raw.len(),
                context: "template field body",
            });
        }
        fields.push(raw[i..end].to_vec());
        i = end;
    }
    Ok(fields)
}

fn decode_ima_ng(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 2 {
        return Err(Error::parse(format!(
            "ima-ng expects 2 fields, got {}",
            fields.len()
        )));
    }
    let digest = decode_d_ng(&fields[0])?;
    let filename = decode_n_ng(&fields[1])?;
    Ok(TemplateData::ImaNg(ImaNgEntry { digest, filename }))
}

fn decode_ima_sig(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 3 {
        return Err(Error::parse(format!(
            "ima-sig expects 3 fields, got {}",
            fields.len()
        )));
    }
    let digest = decode_d_ng(&fields[0])?;
    let filename = decode_n_ng(&fields[1])?;
    let signature = fields[2].clone();
    Ok(TemplateData::ImaSig(ImaSigEntry {
        digest,
        filename,
        signature,
    }))
}

fn decode_ima_buf(fields: &[Vec<u8>]) -> Result<TemplateData> {
    if fields.len() != 3 {
        return Err(Error::parse(format!(
            "ima-buf expects 3 fields, got {}",
            fields.len()
        )));
    }
    let digest = decode_d_ng(&fields[0])?;
    let name = decode_n_ng(&fields[1])?;
    let buf = fields[2].clone();
    Ok(TemplateData::ImaBuf(ImaBufEntry { digest, name, buf }))
}

/// Decode a `d-ng` field: `<algo_name> ":" "\0" <digest_bytes>`.
pub(crate) fn decode_d_ng(raw: &[u8]) -> Result<Digest> {
    // Minimum length: "x:\0" + 1 byte of digest
    if raw.len() < 4 {
        return Err(Error::parse("d-ng field too short"));
    }
    let sep = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::parse("d-ng field missing NUL separator"))?;
    if sep < 2 || raw[sep - 1] != b':' {
        return Err(Error::parse("d-ng field missing ':\\0' separator"));
    }
    let algo_name = std::str::from_utf8(&raw[..sep - 1]).map_err(|_| Error::InvalidUtf8 {
        context: "d-ng algorithm name",
    })?;
    let algo = HashAlgorithm::from_name(algo_name)?;
    let digest_bytes = raw[sep + 1..].to_vec();
    if digest_bytes.len() != algo.digest_size() {
        return Err(Error::InvalidLength {
            value: digest_bytes.len() as u64,
            limit: algo.digest_size() as u64,
            context: "d-ng digest",
        });
    }
    Ok(Digest::new(algo, digest_bytes))
}

/// Decode an `n-ng` field: `<utf-8 bytes> \0`.
pub(crate) fn decode_n_ng(raw: &[u8]) -> Result<String> {
    // Drop the trailing nul if any.
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    let s = std::str::from_utf8(&raw[..end]).map_err(|_| Error::InvalidUtf8 {
        context: "n-ng filename",
    })?;
    Ok(s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_d_ng_sha1() {
        // "sha1" + ":" + "\0" + 20 bytes
        let mut raw = Vec::new();
        raw.extend_from_slice(b"sha1");
        raw.push(b':');
        raw.push(0);
        raw.extend_from_slice(&[0xAB; 20]);
        let d = decode_d_ng(&raw).unwrap();
        assert_eq!(d.algorithm, HashAlgorithm::Sha1);
        assert_eq!(d.bytes, vec![0xAB; 20]);
    }

    #[test]
    fn decode_n_ng_strips_nul() {
        let raw = b"/usr/bin/ls\0";
        assert_eq!(decode_n_ng(raw).unwrap(), "/usr/bin/ls");
    }

    #[test]
    fn parse_ima_ng_roundtrip() {
        // Construct a single ima-ng event by hand.
        let digest = [0xCDu8; 20];
        let mut d_ng = Vec::new();
        d_ng.extend_from_slice(b"sha1");
        d_ng.push(b':');
        d_ng.push(0);
        d_ng.extend_from_slice(&digest);

        let mut n_ng = Vec::new();
        n_ng.extend_from_slice(b"/etc/hosts");
        n_ng.push(0);

        let mut td = Vec::new();
        td.extend_from_slice(&(d_ng.len() as u32).to_le_bytes());
        td.extend_from_slice(&d_ng);
        td.extend_from_slice(&(n_ng.len() as u32).to_le_bytes());
        td.extend_from_slice(&n_ng);

        let mut event = Vec::new();
        event.extend_from_slice(&10u32.to_le_bytes()); // pcr
        event.extend_from_slice(&[0xEE; 20]); // template hash (sha1 sized)
        event.extend_from_slice(&(b"ima-ng".len() as u32).to_le_bytes());
        event.extend_from_slice(b"ima-ng");
        event.extend_from_slice(&(td.len() as u32).to_le_bytes());
        event.extend_from_slice(&td);

        let parser = EventLogParser::new(event.as_slice(), ParseOptions::default());
        let events: Vec<_> = parser.collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.pcr_index, 10);
        assert_eq!(ev.template_name, "ima-ng");
        match &ev.template_data {
            TemplateData::ImaNg(e) => {
                assert_eq!(e.filename, "/etc/hosts");
                assert_eq!(e.digest.algorithm, HashAlgorithm::Sha1);
                assert_eq!(e.digest.bytes, digest);
            }
            other => panic!("expected ImaNg, got {:?}", other),
        }
    }

    #[test]
    fn parse_legacy_ima() {
        let mut td = Vec::new();
        td.extend_from_slice(&[0x11; 20]);
        let mut name = [0u8; IMA_EVENT_NAME_LEN_MAX + 1];
        name[..5].copy_from_slice(b"/init");
        td.extend_from_slice(&name);

        let mut event = Vec::new();
        event.extend_from_slice(&10u32.to_le_bytes());
        event.extend_from_slice(&[0x22; 20]);
        event.extend_from_slice(&(b"ima".len() as u32).to_le_bytes());
        event.extend_from_slice(b"ima");
        event.extend_from_slice(&td);

        let events: Vec<_> = EventLogParser::new(event.as_slice(), ParseOptions::default())
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(events.len(), 1);
        match &events[0].template_data {
            TemplateData::Ima(e) => {
                assert_eq!(e.filename, "/init");
                assert_eq!(e.digest, [0x11; 20]);
            }
            other => panic!("expected Ima, got {:?}", other),
        }
    }
}
