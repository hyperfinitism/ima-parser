// SPDX-License-Identifier: Apache-2.0

//! Template-hash calculator, kept strictly separate from the parser so the
//! same logic is shared between the binary and ASCII paths.

#[cfg(feature = "hash")]
use crate::hash::HashAlgorithm;
use crate::hash::Hasher;

use super::IMA_EVENT_NAME_LEN_MAX;
use super::event::Event;
use super::template::{Template, TemplateData, TemplateField};

/// Internal: reconstruct the per-field framing that appears on the wire so
/// we can feed it into a hash.
///
/// For the legacy `"ima"` template the framing rule in
/// `ima_calc_field_array_hash_tfm()` is:
///
/// * `d` field – 20 bytes raw, **no** length prefix.
/// * `n` field – 256 bytes zero-padded, **no** length prefix.
///
/// For every other template each field becomes `<u32 LE length> || <bytes>`.
pub(super) fn feed_event_into<H: Hasher + ?Sized>(hasher: &mut H, event: &Event) {
    if event.template == Template::Ima {
        feed_legacy_ima(hasher, &event.template_data);
    } else {
        feed_generic(hasher, &event.template_data, &event.template_data_raw);
    }
}

fn feed_legacy_ima<H: Hasher + ?Sized>(hasher: &mut H, data: &TemplateData) {
    match data {
        TemplateData::Ima(entry) => {
            // digest: 20 bytes, no length prefix
            hasher.update(&entry.digest);

            // name: padded to 256 bytes (IMA_EVENT_NAME_LEN_MAX + 1)
            let mut padded = [0u8; IMA_EVENT_NAME_LEN_MAX + 1];
            let name = entry.filename.as_bytes();
            let take = name.len().min(padded.len() - 1); // always keep nul
            padded[..take].copy_from_slice(&name[..take]);
            hasher.update(&padded);
        }
        // If for some reason we ended up with a non-Ima payload wearing the
        // "ima" name, fall back to generic framing so we don't panic.
        other => feed_generic(hasher, other, &[]),
    }
}

fn feed_generic<H: Hasher + ?Sized>(hasher: &mut H, data: &TemplateData, raw: &[u8]) {
    // When we have the raw bytes we parsed out of the log, we can simply
    // re-emit them field by field; the format on disk is already the hash
    // input. Otherwise we re-serialise from the decoded structure.
    if !raw.is_empty() {
        feed_generic_from_raw(hasher, raw);
    } else {
        feed_generic_from_decoded(hasher, data);
    }
}

/// Walk a raw `template_data` blob, emitting `<u32 LE length> || <bytes>`
/// for each framed field into the hasher. This matches exactly what the
/// kernel does in `ima_calc_field_array_hash_tfm()` for non-`"ima"`
/// templates.
fn feed_generic_from_raw<H: Hasher + ?Sized>(hasher: &mut H, raw: &[u8]) {
    let mut i = 0;
    while i + 4 <= raw.len() {
        let len = u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        i += 4;
        let end = i.saturating_add(len as usize);
        if end > raw.len() {
            // Malformed framing: stop rather than panic. The caller has
            // already been told the data length header by the parser, so
            // this should never happen in practice.
            return;
        }
        hasher.update(&len.to_le_bytes());
        hasher.update(&raw[i..end]);
        i = end;
    }
}

fn feed_generic_from_decoded<H: Hasher + ?Sized>(hasher: &mut H, data: &TemplateData) {
    let fields = collect_fields(data);
    for f in fields {
        hasher.update(&(f.data.len() as u32).to_le_bytes());
        hasher.update(&f.data);
    }
}

fn collect_fields(data: &TemplateData) -> Vec<TemplateField> {
    match data {
        TemplateData::Ima(_) => Vec::new(),
        TemplateData::ImaNg(e) => vec![
            TemplateField {
                data: encode_d_ng(&e.digest),
            },
            TemplateField {
                data: encode_n_ng(&e.filename),
            },
        ],
        TemplateData::ImaSig(e) => vec![
            TemplateField {
                data: encode_d_ng(&e.digest),
            },
            TemplateField {
                data: encode_n_ng(&e.filename),
            },
            TemplateField {
                data: e.signature.clone(),
            },
        ],
        TemplateData::ImaBuf(e) => vec![
            TemplateField {
                data: encode_d_ng(&e.digest),
            },
            TemplateField {
                data: encode_n_ng(&e.name),
            },
            TemplateField {
                data: e.buf.clone(),
            },
        ],
        TemplateData::ImaModsig(e) => vec![
            TemplateField {
                data: encode_d_ng(&e.digest),
            },
            TemplateField {
                data: encode_n_ng(&e.filename),
            },
            TemplateField {
                data: e.signature.clone(),
            },
            TemplateField {
                data: e.modsig_digest.as_ref().map_or_else(Vec::new, encode_d_ng),
            },
            TemplateField {
                data: e.modsig.clone(),
            },
        ],
        TemplateData::ImaNgV2(e) => vec![
            TemplateField {
                data: encode_d_ngv2(&e.digest),
            },
            TemplateField {
                data: encode_n_ng(&e.filename),
            },
        ],
        TemplateData::ImaSigV2(e) => vec![
            TemplateField {
                data: encode_d_ngv2(&e.digest),
            },
            TemplateField {
                data: encode_n_ng(&e.filename),
            },
            TemplateField {
                data: e.signature.clone(),
            },
        ],
        TemplateData::EvmSig(e) => vec![
            TemplateField {
                data: encode_d_ng(&e.digest),
            },
            TemplateField {
                data: encode_n_ng(&e.filename),
            },
            TemplateField {
                data: e.evmsig.clone(),
            },
            TemplateField {
                data: encode_n_ng(&e.xattrnames),
            },
            TemplateField {
                data: e.xattrlengths.clone(),
            },
            TemplateField {
                data: e.xattrvalues.clone(),
            },
            TemplateField {
                data: e.iuid.to_le_bytes().to_vec(),
            },
            TemplateField {
                data: e.igid.to_le_bytes().to_vec(),
            },
            TemplateField {
                data: e.imode.to_le_bytes().to_vec(),
            },
        ],
        TemplateData::Unknown(fields) => fields.clone(),
    }
}

pub(crate) fn encode_d_ng(digest: &crate::log::Digest) -> Vec<u8> {
    let name = digest.algorithm.name().as_bytes();
    let mut out = Vec::with_capacity(name.len() + 2 + digest.bytes.len());
    out.extend_from_slice(name);
    out.push(b':');
    out.push(0);
    out.extend_from_slice(&digest.bytes);
    out
}

pub(crate) fn encode_n_ng(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 1);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out
}
pub(crate) fn encode_d_ngv2(digest: &crate::log::DigestV2) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(digest.digest_type.as_str().as_bytes());
    out.push(b':');
    out.extend_from_slice(digest.digest.algorithm.name().as_bytes());
    out.push(b':');
    out.push(0);
    out.extend_from_slice(&digest.digest.bytes);
    out
}

#[cfg(feature = "hash")]
pub(super) fn calculate_with(event: &Event, algo: HashAlgorithm) -> Option<Vec<u8>> {
    let mut hasher = algo.hasher()?;
    feed_event_into(hasher.as_mut(), event);
    Some(hasher.finalize())
}

pub(super) fn calculate_with_hasher(event: &Event, mut hasher: Box<dyn Hasher>) -> Vec<u8> {
    feed_event_into(hasher.as_mut(), event);
    hasher.finalize()
}
