// SPDX-License-Identifier: Apache-2.0

//! Integration tests that exercise the parsers against real-world fixtures
//! captured from a Linux VM (see `testdata/`).

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use ima_parser::hash::HashAlgorithm;
use ima_parser::log::{Endianness, EventLogParser, ParseOptions, TemplateData, parse_ascii_log};
use ima_parser::policy::parse_policy;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(rel)
}

const TEMPLATE_HASH_ALGOS: &[(HashAlgorithm, &str)] = &[
    (HashAlgorithm::Sha1, "sha1"),
    (HashAlgorithm::Sha256, "sha256"),
    (HashAlgorithm::Sha384, "sha384"),
];

#[test]
fn parses_builtin_tcb_policy() {
    let text = fs::read_to_string(testdata("policies/builtin-tcb-policy")).unwrap();
    let policy = parse_policy(&text).unwrap();
    let non_blank = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .count();
    assert_eq!(policy.rules.len(), non_blank);
    assert!(!policy.rules.is_empty());
}

#[test]
fn parses_builtin_tcb_appraise_policy() {
    let text = fs::read_to_string(testdata("policies/builtin-tcb-appraise-policy")).unwrap();
    let policy = parse_policy(&text).unwrap();
    let non_blank = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .count();
    assert_eq!(policy.rules.len(), non_blank);
    assert!(!policy.rules.is_empty());
}

#[test]
fn parses_custom_ima_policy() {
    let text = fs::read_to_string(testdata("policies/custom-ima-policy")).unwrap();
    let policy = parse_policy(&text).unwrap();
    let non_blank = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .count();
    assert_eq!(policy.rules.len(), non_blank);
}

#[test]
fn parses_all_ascii_logs() {
    for (algo, name) in TEMPLATE_HASH_ALGOS {
        let path = testdata(&format!("logs/ascii_runtime_measurements_{name}"));
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let events =
            parse_ascii_log(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        assert!(!events.is_empty(), "{}: no events parsed", path.display());

        for (i, ev) in events.iter().enumerate() {
            assert_eq!(
                ev.template_hash.len(),
                algo.digest_size(),
                "{}: event {i} has wrong template_hash size",
                path.display(),
            );
            assert_eq!(
                ev.pcr_index,
                10,
                "{}: event {i} unexpected PCR",
                path.display()
            );
        }
    }
}

#[cfg(feature = "hash")]
#[test]
fn ascii_logs_template_hashes_verify() {
    for (algo, name) in TEMPLATE_HASH_ALGOS {
        let path = testdata(&format!("logs/ascii_runtime_measurements_{name}"));
        let text = fs::read_to_string(&path).unwrap();
        let events = parse_ascii_log(&text).unwrap();

        // The first event of any IMA log is `boot_aggregate`, whose
        // template_hash field in the ASCII rendering is computed by the
        // kernel from the PCR bank (typically PCR[0]..PCR[9]), is not
        // reproducible from the template data alone (it deliberately
        // differs between ascii_runtime_measurements files for different
        // banks). Skip it.
        for (i, ev) in events.iter().enumerate().skip(1) {
            assert_eq!(
                ev.verify_template_hash(*algo),
                Some(true),
                "{}: event {i} ({}) failed template-hash verification",
                path.display(),
                ev.template.as_str(),
            );
        }
    }
}

#[test]
fn parses_all_binary_logs() {
    for (algo, name) in TEMPLATE_HASH_ALGOS {
        let path = testdata(&format!("logs/binary_runtime_measurements_{name}"));
        let file = fs::File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
        let opts = ParseOptions::default()
            .with_endianness(Endianness::Little)
            .with_template_hash_algorithm(*algo);
        let events: Vec<_> = EventLogParser::new(BufReader::new(file), opts)
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

        assert!(!events.is_empty(), "{}: no events parsed", path.display());
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(
                ev.template_hash.len(),
                algo.digest_size(),
                "{}: event {i} has wrong template_hash size",
                path.display(),
            );
        }
    }
}

#[cfg(feature = "hash")]
#[test]
fn binary_logs_template_hashes_verify() {
    for (algo, name) in TEMPLATE_HASH_ALGOS {
        let path = testdata(&format!("logs/binary_runtime_measurements_{name}"));
        let file = fs::File::open(&path).unwrap();
        let opts = ParseOptions::default()
            .with_endianness(Endianness::Little)
            .with_template_hash_algorithm(*algo);
        let events: Vec<_> = EventLogParser::new(BufReader::new(file), opts)
            .collect::<Result<_, _>>()
            .unwrap();

        for (i, ev) in events.iter().enumerate().skip(1) {
            assert_eq!(
                ev.verify_template_hash(*algo),
                Some(true),
                "{}: event {i} ({}) failed template-hash verification",
                path.display(),
                ev.template.as_str(),
            );
        }
    }
}

#[test]
fn ascii_and_binary_logs_agree() {
    for (algo, name) in TEMPLATE_HASH_ALGOS {
        let ascii_path = testdata(&format!("logs/ascii_runtime_measurements_{name}"));
        let binary_path = testdata(&format!("logs/binary_runtime_measurements_{name}"));

        let ascii_text = fs::read_to_string(&ascii_path).unwrap();
        let ascii_events = parse_ascii_log(&ascii_text).unwrap();

        let binary_file = fs::File::open(&binary_path).unwrap();
        let opts = ParseOptions::default()
            .with_endianness(Endianness::Little)
            .with_template_hash_algorithm(*algo);
        let binary_events: Vec<_> = EventLogParser::new(BufReader::new(binary_file), opts)
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(
            ascii_events.len(),
            binary_events.len(),
            "{name}: event count differs between ASCII and binary logs",
        );

        for (i, (a, b)) in ascii_events.iter().zip(binary_events.iter()).enumerate() {
            assert_eq!(a.pcr_index, b.pcr_index, "event {i}: pcr differs");
            assert_eq!(
                a.template.as_str(),
                b.template.as_str(),
                "event {i}: template name differs",
            );
            // The first event is `boot_aggregate`; its template_hash differs
            // between banks but the decoded template_data should still match.
            assert!(
                template_payload_eq(&a.template_data, &b.template_data),
                "event {i} ({}): template_data differs between ASCII and binary",
                a.template.as_str(),
            );
            if i > 0 {
                assert_eq!(
                    a.template_hash,
                    b.template_hash,
                    "event {i} ({}): template_hash differs between ASCII and binary",
                    a.template.as_str(),
                );
            }
        }
    }
}

fn template_payload_eq(a: &TemplateData, b: &TemplateData) -> bool {
    match (a, b) {
        (TemplateData::Ima(x), TemplateData::Ima(y)) => x == y,
        (TemplateData::ImaNg(x), TemplateData::ImaNg(y)) => x == y,
        (TemplateData::ImaSig(x), TemplateData::ImaSig(y)) => {
            x.filename == y.filename && x.digest == y.digest
        }
        (TemplateData::ImaBuf(x), TemplateData::ImaBuf(y)) => {
            x.name == y.name && x.digest == y.digest
        }
        _ => false,
    }
}
