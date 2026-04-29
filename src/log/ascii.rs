// SPDX-License-Identifier: Apache-2.0

//! ASCII IMA event-log parser.
//!
//! The format of `/sys/kernel/security/ima/ascii_runtime_measurements_*` is:
//!
//! ```text
//! <pcr> <template_hash_hex> <template> <template_specific fields…>
//! ```
//!
//! with SP (`' '`) as the token separator and LF (`'\n'`) as the record
//! separator. Template-specific fields are:
//!
//! - `ima`: `d | n`
//! - `ima-ng`: `d-ng | n-ng`
//! - `ima-ngv2`: `d-ngv2 | n-ng`
//! - `ima-sig`: `d-ng | n-ng | sig`
//! - `ima-sigv2`: `d-ngv2 | n-ng | sig`
//! - `ima-buf`: `d-ng | n-ng | buf`
//! - `ima-modsig`: `d-ng | n-ng | sig | d-modsig | modsig`
//! - `evm-sig`: `d-ng | n-ng | evmsig | xattrnames | xattrlengths | xattrvalues | iuid | igid | imode`
//!
//! The `filename` may contain spaces; the kernel escapes those as `\x20`.

use crate::error::{Error, Result};
use crate::hash::HashAlgorithm;

use super::event::Event;
use super::template::{
    Digest, DigestType, DigestV2, EvmSigEntry, ImaBufEntry, ImaEntry, ImaModsigEntry, ImaNgEntry,
    ImaNgV2Entry, ImaSigEntry, ImaSigV2Entry, Template, TemplateData, TemplateField,
};

/// Parse an entire ASCII measurement log (one event per line).
///
/// Lines that are blank or begin with `#` are skipped so the helper can be
/// reused with annotated files.
pub fn parse_ascii_log(input: &str) -> Result<Vec<Event>> {
    let mut out = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(
            parse_ascii_line(trimmed)
                .map_err(|e| Error::parse(format!("line {}: {}", i + 1, e)))?,
        );
    }
    Ok(out)
}

/// Parse exactly one ASCII event-log line.
pub fn parse_ascii_line(line: &str) -> Result<Event> {
    let mut toks = line.split_whitespace();

    let pcr = toks
        .next()
        .ok_or_else(|| Error::malformed("missing PCR index"))?;
    let pcr_index: u32 = pcr
        .parse()
        .map_err(|_| Error::malformed(format!("invalid PCR `{pcr}`")))?;

    let template_hash_hex = toks
        .next()
        .ok_or_else(|| Error::malformed("missing template hash"))?;
    let template_hash = decode_hex(template_hash_hex)?;

    let template_name = toks
        .next()
        .ok_or_else(|| Error::malformed("missing template name"))?
        .to_owned();
    let template = Template::parse(&template_name);

    let rest: Vec<&str> = toks.collect();
    let (template_data, template_data_raw) = parse_template_payload(&template, &rest)?;

    Ok(Event {
        pcr_index,
        template_hash,
        template,
        template_data,
        template_data_raw,
    })
}

fn parse_template_payload(template: &Template, fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    match template {
        Template::ImaNg => parse_ima_ng(fields),
        Template::ImaSig => parse_ima_sig(fields),
        Template::ImaBuf => parse_ima_buf(fields),
        Template::ImaModsig => parse_ima_modsig(fields),
        Template::ImaNgV2 => parse_ima_ngv2(fields),
        Template::ImaSigV2 => parse_ima_sigv2(fields),
        Template::EvmSig => parse_evm_sig(fields),
        Template::Ima => parse_legacy_ima(fields),
        _ => {
            // Unknown template: preserve every whitespace-separated token as
            // its own opaque field so callers can still inspect the payload.
            // We have no way to know the kernel's wire framing for this
            // template, so `template_data_raw` stays empty and the template
            // hash recomputation will hash `<u32 LE len> || token` per field
            // — close to the kernel's framing for most real templates, but
            // not guaranteed to match for templates whose ASCII rendering
            // re-encodes binary payloads (e.g. hex-encoded blobs).
            let unknown = fields
                .iter()
                .map(|tok| TemplateField {
                    data: tok.as_bytes().to_vec(),
                })
                .collect();
            Ok((TemplateData::Unknown(unknown), Vec::new()))
        }
    }
}

fn parse_ima_ngv2(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 2 {
        return Err(Error::malformed(
            "ima-ngv2 expects <dtype:algo:hex> <filename>",
        ));
    }
    let digest = parse_prefixed_digest_v2(fields[0])?;
    let filename = unescape_filename(&fields[1..].join(" "));
    let raw = Vec::new();
    Ok((
        TemplateData::ImaNgV2(ImaNgV2Entry { digest, filename }),
        raw,
    ))
}

fn parse_ima_sigv2(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 2 {
        return Err(Error::malformed(
            "ima-sigv2 expects <dtype:algo:hex> <filename> [<sig>]",
        ));
    }
    let digest = parse_prefixed_digest_v2(fields[0])?;
    let (filename, signature) = if fields.len() >= 3 && looks_like_hex(fields[fields.len() - 1]) {
        (
            unescape_filename(&fields[1..fields.len() - 1].join(" ")),
            decode_hex(fields[fields.len() - 1])?,
        )
    } else {
        (unescape_filename(&fields[1..].join(" ")), Vec::new())
    };
    Ok((
        TemplateData::ImaSigV2(ImaSigV2Entry {
            digest,
            filename,
            signature,
        }),
        Vec::new(),
    ))
}

fn parse_ima_modsig(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 3 {
        return Err(Error::malformed(
            "ima-modsig expects <digest> <filename> <sig> [<d-modsig>] [<modsig>]",
        ));
    }
    let digest = parse_prefixed_digest(fields[0])?;
    let filename = unescape_filename(fields[1]);
    let signature = decode_hex(fields[2])?;
    let modsig_digest = fields
        .get(3)
        .map(|s| decode_hex(s))
        .transpose()?
        .unwrap_or_default();
    let modsig = fields
        .get(4)
        .map(|s| decode_hex(s))
        .transpose()?
        .unwrap_or_default();
    Ok((
        TemplateData::ImaModsig(ImaModsigEntry {
            digest,
            filename,
            signature,
            modsig_digest,
            modsig,
        }),
        Vec::new(),
    ))
}

fn parse_evm_sig(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 9 {
        return Err(Error::malformed("evm-sig expects 9 template fields"));
    }
    let digest = parse_prefixed_digest(fields[0])?;
    let iuid: u32 = fields[6]
        .parse()
        .map_err(|_| Error::malformed("invalid iuid"))?;
    let igid: u32 = fields[7]
        .parse()
        .map_err(|_| Error::malformed("invalid igid"))?;
    let imode: u16 = fields[8]
        .parse()
        .map_err(|_| Error::malformed("invalid imode"))?;
    Ok((
        TemplateData::EvmSig(EvmSigEntry {
            digest,
            filename: unescape_filename(fields[1]),
            evmsig: decode_hex(fields[2])?,
            xattrnames: unescape_filename(fields[3]),
            xattrlengths: decode_hex(fields[4])?,
            xattrvalues: decode_hex(fields[5])?,
            iuid,
            igid,
            imode,
        }),
        Vec::new(),
    ))
}

fn parse_ima_ng(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 2 {
        return Err(Error::malformed("ima-ng expects <digest> <filename>"));
    }
    let digest = parse_prefixed_digest(fields[0])?;
    let filename = unescape_filename(&fields[1..].join(" "));

    // Rebuild the wire bytes so template-hash computation can run.
    let raw = rebuild_ima_ng(&digest, &filename);
    Ok((TemplateData::ImaNg(ImaNgEntry { digest, filename }), raw))
}

fn parse_ima_sig(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 2 {
        return Err(Error::malformed(
            "ima-sig expects <digest> <filename> [<sig>]",
        ));
    }
    let digest = parse_prefixed_digest(fields[0])?;
    // The last token is the signature hex if it looks purely hex AND is
    // non-empty AND we have more than 2 tokens.
    let (filename, signature) = if fields.len() >= 3 && looks_like_hex(fields[fields.len() - 1]) {
        let sig = decode_hex(fields[fields.len() - 1])?;
        let name = unescape_filename(&fields[1..fields.len() - 1].join(" "));
        (name, sig)
    } else {
        (unescape_filename(&fields[1..].join(" ")), Vec::new())
    };
    let raw = rebuild_ima_sig(&digest, &filename, &signature);
    Ok((
        TemplateData::ImaSig(ImaSigEntry {
            digest,
            filename,
            signature,
        }),
        raw,
    ))
}

fn parse_ima_buf(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 3 {
        return Err(Error::malformed(
            "ima-buf expects <digest> <name> <buffer-hex>",
        ));
    }
    let digest = parse_prefixed_digest(fields[0])?;
    let buf = decode_hex(fields[fields.len() - 1])?;
    let name = unescape_filename(&fields[1..fields.len() - 1].join(" "));
    let raw = rebuild_ima_buf(&digest, &name, &buf);
    Ok((TemplateData::ImaBuf(ImaBufEntry { digest, name, buf }), raw))
}

fn parse_legacy_ima(fields: &[&str]) -> Result<(TemplateData, Vec<u8>)> {
    if fields.len() < 2 {
        return Err(Error::malformed("ima expects <digest-hex> <filename>"));
    }
    let digest_bytes = decode_hex(fields[0])?;
    if digest_bytes.len() != 20 {
        return Err(Error::InvalidLength {
            value: digest_bytes.len() as u64,
            limit: 20,
            context: "legacy ima digest",
        });
    }
    let mut digest = [0u8; 20];
    digest.copy_from_slice(&digest_bytes);
    let filename = unescape_filename(&fields[1..].join(" "));

    // Reconstruct the 276-byte wire payload.
    let mut raw = Vec::with_capacity(276);
    raw.extend_from_slice(&digest);
    let mut padded = [0u8; super::IMA_EVENT_NAME_LEN_MAX + 1];
    let name_bytes = filename.as_bytes();
    let take = name_bytes.len().min(padded.len() - 1);
    padded[..take].copy_from_slice(&name_bytes[..take]);
    raw.extend_from_slice(&padded);

    Ok((TemplateData::Ima(ImaEntry { digest, filename }), raw))
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

fn parse_prefixed_digest(s: &str) -> Result<Digest> {
    let (algo_name, hex) = s
        .split_once(':')
        .ok_or_else(|| Error::malformed(format!("expected `<algo>:<hex>`, got `{s}`")))?;
    let algo = HashAlgorithm::from_name(algo_name)?;
    let bytes = decode_hex(hex)?;
    if bytes.len() != algo.digest_size() {
        return Err(Error::InvalidLength {
            value: bytes.len() as u64,
            limit: algo.digest_size() as u64,
            context: "digest",
        });
    }
    Ok(Digest::new(algo, bytes))
}
fn parse_prefixed_digest_v2(s: &str) -> Result<DigestV2> {
    let mut it = s.splitn(3, ':');
    let dtype = it
        .next()
        .ok_or_else(|| Error::malformed("missing digest type"))?;
    let algo_name = it
        .next()
        .ok_or_else(|| Error::malformed("missing algorithm"))?;
    let hex = it
        .next()
        .ok_or_else(|| Error::malformed("missing digest hex"))?;
    let digest = parse_prefixed_digest(&format!("{algo_name}:{hex}"))?;
    Ok(DigestV2 {
        digest_type: DigestType::parse(dtype),
        digest,
    })
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::parse(format!("odd-length hex string `{s}`")));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::parse(format!("invalid hex nibble `{}`", b as char))),
    }
}

fn looks_like_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Undo the kernel's `\x20`, `\\n`, `\\r`, `\\t`, `\\\\` escaping.
fn unescape_filename(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                    continue;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                    continue;
                }
                b'x' | b'X' if i + 3 < bytes.len() => {
                    if let (Ok(hi), Ok(lo)) = (hex_nibble(bytes[i + 2]), hex_nibble(bytes[i + 3])) {
                        out.push((hi << 4) | lo);
                        i += 4;
                        continue;
                    }
                }
                _ => {}
            }
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn rebuild_ima_ng(digest: &Digest, filename: &str) -> Vec<u8> {
    let d = super::template_hash::encode_d_ng(digest);
    let n = super::template_hash::encode_n_ng(filename);
    let mut out = Vec::with_capacity(8 + d.len() + n.len());
    out.extend_from_slice(&(d.len() as u32).to_le_bytes());
    out.extend_from_slice(&d);
    out.extend_from_slice(&(n.len() as u32).to_le_bytes());
    out.extend_from_slice(&n);
    out
}

fn rebuild_ima_sig(digest: &Digest, filename: &str, sig: &[u8]) -> Vec<u8> {
    let d = super::template_hash::encode_d_ng(digest);
    let n = super::template_hash::encode_n_ng(filename);
    let mut out = Vec::with_capacity(12 + d.len() + n.len() + sig.len());
    out.extend_from_slice(&(d.len() as u32).to_le_bytes());
    out.extend_from_slice(&d);
    out.extend_from_slice(&(n.len() as u32).to_le_bytes());
    out.extend_from_slice(&n);
    out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    out.extend_from_slice(sig);
    out
}

fn rebuild_ima_buf(digest: &Digest, name: &str, buf: &[u8]) -> Vec<u8> {
    let d = super::template_hash::encode_d_ng(digest);
    let n = super::template_hash::encode_n_ng(name);
    let mut out = Vec::with_capacity(12 + d.len() + n.len() + buf.len());
    out.extend_from_slice(&(d.len() as u32).to_le_bytes());
    out.extend_from_slice(&d);
    out.extend_from_slice(&(n.len() as u32).to_le_bytes());
    out.extend_from_slice(&n);
    out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
    out.extend_from_slice(buf);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_boot_aggregate_line() {
        let line = "10 91f34b5c671d73504b274a919661cf80dab1e127 ima-ng \
                    sha1:1801e1be3e65ef1eaa5c16617bec8f1274eaf6b3 boot_aggregate";
        let ev = parse_ascii_line(line).unwrap();
        assert_eq!(ev.pcr_index, 10);
        assert_eq!(ev.template.as_str(), "ima-ng");
        match &ev.template_data {
            TemplateData::ImaNg(e) => {
                assert_eq!(e.digest.algorithm, HashAlgorithm::Sha1);
                assert_eq!(e.filename, "boot_aggregate");
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn parse_comment_and_blank_lines() {
        let input = "\
# comment\n\
\n\
10 91f34b5c671d73504b274a919661cf80dab1e127 ima-ng \
sha1:1801e1be3e65ef1eaa5c16617bec8f1274eaf6b3 /init\n\
";
        let events = parse_ascii_log(input).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn unescape_paths() {
        assert_eq!(unescape_filename(r"/tmp/a\x20b"), "/tmp/a b");
        assert_eq!(unescape_filename(r"a\\b"), "a\\b");
    }

    #[test]
    fn unknown_template_preserves_tokens() {
        // A made-up template name that the parser doesn't recognise: the
        // remaining tokens must come back as opaque fields so callers can
        // still see them.
        let line = "10 \
                    deadbeefdeadbeefdeadbeefdeadbeefdeadbeef \
                    weird-template foo bar baz";
        let ev = parse_ascii_line(line).unwrap();
        assert_eq!(ev.template.as_str(), "weird-template");
        match &ev.template_data {
            TemplateData::Unknown(fields) => {
                let strs: Vec<&[u8]> = fields.iter().map(|f| f.data.as_slice()).collect();
                assert_eq!(strs, vec![&b"foo"[..], &b"bar"[..], &b"baz"[..]]);
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn sig_hex_recognised_as_last_field() {
        let line = "10 f63c10947347c71ff205ebfde5971009af27b0ba ima-sig \
                    sha256:6c118980083bccd259f069c2b3c3f3a2f5302d17a685409786564f4cf05b3939 \
                    /usr/lib64/libgspell-1.so.1.0.0 0302046e6c10460100aa";
        let ev = parse_ascii_line(line).unwrap();
        match &ev.template_data {
            TemplateData::ImaSig(e) => {
                assert_eq!(e.filename, "/usr/lib64/libgspell-1.so.1.0.0");
                assert_eq!(e.signature.len(), 10);
            }
            other => panic!("{:?}", other),
        }
    }
}
