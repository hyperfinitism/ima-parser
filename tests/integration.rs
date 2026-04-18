// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests: build a log in memory, parse it back, and verify
//! template-hash recomputation.

use ima_parser::hash::HashAlgorithm;
use ima_parser::log::{
    Digest, Endianness, EventLogParser, ParseOptions, TemplateData, parse_ascii_log,
};

/// Helper: encode one `ima-ng` event into the binary log format.
fn build_ima_ng_event(pcr: u32, template_hash: &[u8], digest: &Digest, filename: &str) -> Vec<u8> {
    let mut d_ng = Vec::new();
    d_ng.extend_from_slice(digest.algorithm.name().as_bytes());
    d_ng.push(b':');
    d_ng.push(0);
    d_ng.extend_from_slice(&digest.bytes);

    let mut n_ng = Vec::new();
    n_ng.extend_from_slice(filename.as_bytes());
    n_ng.push(0);

    let mut td = Vec::new();
    td.extend_from_slice(&(d_ng.len() as u32).to_le_bytes());
    td.extend_from_slice(&d_ng);
    td.extend_from_slice(&(n_ng.len() as u32).to_le_bytes());
    td.extend_from_slice(&n_ng);

    let mut event = Vec::new();
    event.extend_from_slice(&pcr.to_le_bytes());
    event.extend_from_slice(template_hash);
    event.extend_from_slice(&(b"ima-ng".len() as u32).to_le_bytes());
    event.extend_from_slice(b"ima-ng");
    event.extend_from_slice(&(td.len() as u32).to_le_bytes());
    event.extend_from_slice(&td);
    event
}

#[test]
fn binary_parser_yields_multiple_events() {
    let d = Digest::new(HashAlgorithm::Sha256, vec![0xAA; 32]);
    let mut log = Vec::new();
    log.extend_from_slice(&build_ima_ng_event(10, &[0x01; 20], &d, "/usr/bin/ls"));
    log.extend_from_slice(&build_ima_ng_event(10, &[0x02; 20], &d, "/etc/passwd"));

    let opts = ParseOptions::default()
        .with_endianness(Endianness::Little)
        .with_template_hash_algorithm(HashAlgorithm::Sha1);
    let events: Vec<_> = EventLogParser::new(log.as_slice(), opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].template_name, "ima-ng");
}

#[cfg(feature = "hash")]
#[test]
fn template_hash_recomputation_matches() {
    // Build an ima-ng event with a known payload, let the parser compute
    // the template hash, then verify the stored hash equals the recomputed
    // one.
    let d = Digest::new(HashAlgorithm::Sha256, vec![0x42; 32]);

    // Reconstruct the exact bytes that the template hash must cover.
    let mut d_ng = Vec::new();
    d_ng.extend_from_slice(b"sha256");
    d_ng.push(b':');
    d_ng.push(0);
    d_ng.extend_from_slice(&d.bytes);

    let n_ng = {
        let mut v = Vec::new();
        v.extend_from_slice(b"/bin/sh");
        v.push(0);
        v
    };

    // Compute the expected SHA-1 template hash manually.
    use sha1::{Digest as _, Sha1};
    let mut h = Sha1::new();
    h.update((d_ng.len() as u32).to_le_bytes());
    h.update(&d_ng);
    h.update((n_ng.len() as u32).to_le_bytes());
    h.update(&n_ng);
    let expected: Vec<u8> = h.finalize().to_vec();

    let event_bytes = build_ima_ng_event(10, &expected, &d, "/bin/sh");
    let opts = ParseOptions::default().with_template_hash_algorithm(HashAlgorithm::Sha1);
    let events: Vec<_> = EventLogParser::new(event_bytes.as_slice(), opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(events.len(), 1);
    let recomputed = events[0]
        .calculate_template_hash(HashAlgorithm::Sha1)
        .unwrap();
    assert_eq!(recomputed, expected);
    assert_eq!(
        events[0].verify_template_hash(HashAlgorithm::Sha1),
        Some(true)
    );
}

#[cfg(feature = "hash")]
#[test]
fn legacy_ima_template_hash() {
    // Legacy "ima" template: hash(20-byte digest || 256-byte zero-padded name).
    use ima_parser::log::{EventLogParser, IMA_EVENT_NAME_LEN_MAX};
    use sha1::{Digest as _, Sha1};

    let digest = [0xEFu8; 20];
    let name = "/init";

    let mut expected = Sha1::new();
    expected.update(digest);
    let mut padded = [0u8; IMA_EVENT_NAME_LEN_MAX + 1];
    padded[..name.len()].copy_from_slice(name.as_bytes());
    expected.update(padded);
    let expected: Vec<u8> = expected.finalize().to_vec();

    // Build a log with that template hash.
    let mut event = Vec::new();
    event.extend_from_slice(&10u32.to_le_bytes());
    event.extend_from_slice(&expected);
    event.extend_from_slice(&(b"ima".len() as u32).to_le_bytes());
    event.extend_from_slice(b"ima");
    event.extend_from_slice(&digest);
    event.extend_from_slice(&padded);

    let opts = ParseOptions::default().with_template_hash_algorithm(HashAlgorithm::Sha1);
    let events: Vec<_> = EventLogParser::new(event.as_slice(), opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        events[0].verify_template_hash(HashAlgorithm::Sha1),
        Some(true)
    );
}

#[test]
fn ascii_and_binary_agree_on_decoded_form() {
    let d = Digest::new(HashAlgorithm::Sha1, vec![0xCC; 20]);
    let binary = build_ima_ng_event(10, &[0x00; 20], &d, "/etc/hosts");
    let opts = ParseOptions::default().with_template_hash_algorithm(HashAlgorithm::Sha1);
    let from_binary = EventLogParser::new(binary.as_slice(), opts)
        .next()
        .unwrap()
        .unwrap();

    let ascii_line = format!(
        "10 {} ima-ng sha1:{} /etc/hosts",
        "00".repeat(20),
        "cc".repeat(20),
    );
    let from_ascii = parse_ascii_log(&ascii_line).unwrap().remove(0);

    assert_eq!(from_binary.pcr_index, from_ascii.pcr_index);
    assert_eq!(from_binary.template_name, from_ascii.template_name);
    match (&from_binary.template_data, &from_ascii.template_data) {
        (TemplateData::ImaNg(a), TemplateData::ImaNg(b)) => {
            assert_eq!(a, b);
        }
        other => panic!("{:?}", other),
    }
}
