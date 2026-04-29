// SPDX-License-Identifier: Apache-2.0

//! Type definitions and parsers for the Linux **Integrity Measurement
//! Architecture** (IMA), based on the upstream specification at
//! <https://ima-doc.readthedocs.io/>.
//!
//! Two artefacts produced by IMA are supported:
//!
//! * The **event log** (measurement list / integrity log) exposed by the
//!   kernel via `securityfs`:
//!   * `/sys/kernel/security/ima/binary_runtime_measurements`
//!   * `/sys/kernel/security/ima/ascii_runtime_measurements`
//!
//!   Both *binary* and *ASCII* representations can be parsed, and the
//!   `template_hash` of every event can be recomputed and verified using the
//!   built-in [`Hasher`](crate::hash::Hasher) implementations.
//!
//! * The **policy** file (`/etc/ima/ima-policy`,
//!   `/sys/kernel/security/ima/policy`, …): an ordered list of rules
//!   composed of an action, conditions and options.
//!
//! ## Quick tour
//!
//! ### Parsing an IMA policy
//!
//! ```
//! use ima_parser::policy::{parse_policy, Action};
//!
//! let text = concat!(
//!     "# measure all executables run\n",
//!     "measure func=BPRM_CHECK\n",
//!     "dont_measure fsmagic=0x9fa0\n",
//! );
//! let policy = parse_policy(text).unwrap();
//! assert_eq!(policy.rules.len(), 2);
//! assert_eq!(policy.rules[0].action, Action::Measure);
//! ```
//!
//! ### Parsing the binary log
//!
//! ```no_run
//! use ima_parser::log::{EventLogParser, ParseOptions};
//! use ima_parser::hash::HashAlgorithm;
//!
//! let bytes = std::fs::read("/sys/kernel/security/ima/binary_runtime_measurements")?;
//! // The default file is hashed with SHA-1; for the SHA-256 variant use
//! // `with_template_hash_algorithm`.
//! let opts = ParseOptions::default()
//!     .with_template_hash_algorithm(HashAlgorithm::Sha1);
//! for event in EventLogParser::new(bytes.as_slice(), opts) {
//!     let event = event?;
//!     println!("PCR {} {}", event.pcr_index, event.template);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Parsing the ASCII log
//!
//! ```
//! use ima_parser::log::parse_ascii_log;
//!
//! let line = "10 91f34b5c671d73504b274a919661cf80dab1e127 ima-ng sha1:1801e1be3e65ef1eaa5c16617bec8f1274eaf6b3 boot_aggregate\n";
//! let events = parse_ascii_log(line).unwrap();
//! assert_eq!(events.len(), 1);
//! assert_eq!(events[0].template.as_str(), "ima-ng");
//! ```
//!
//! ### Recomputing a template hash
//!
//! ```
//! # #[cfg(feature = "hash")] {
//! use ima_parser::hash::HashAlgorithm;
//! use ima_parser::log::parse_ascii_log;
//!
//! // Build a self-consistent synthetic event by first computing the
//! // template hash for a known (digest, filename) pair, then feeding the
//! // result back through the ASCII parser.
//! use sha1::{Digest, Sha1};
//! let filedata_hex = "cd".repeat(20);
//! let filename = "/etc/hosts";
//! let mut d_ng = Vec::new();
//! d_ng.extend_from_slice(b"sha1");
//! d_ng.push(b':');
//! d_ng.push(0);
//! d_ng.extend_from_slice(&[0xcd; 20]);
//! let mut n_ng = Vec::new();
//! n_ng.extend_from_slice(filename.as_bytes());
//! n_ng.push(0);
//! let mut h = Sha1::new();
//! h.update((d_ng.len() as u32).to_le_bytes());
//! h.update(&d_ng);
//! h.update((n_ng.len() as u32).to_le_bytes());
//! h.update(&n_ng);
//! let th_hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
//!
//! let line = format!("10 {} ima-ng sha1:{} {}\n", th_hex, filedata_hex, filename);
//! let events = parse_ascii_log(&line).unwrap();
//! assert_eq!(events[0].verify_template_hash(HashAlgorithm::Sha1), Some(true));
//! # }
//! ```
//!
//! ## Cargo features
//!
//! * `hash` *(default)* — enables built-in template-hash computation via the
//!   `sha1` and `sha2` crates from RustCrypto. Disabling it removes both
//!   dependencies; you can still implement the [`Hasher`](crate::hash::Hasher)
//!   trait against your own crypto stack.

#![deny(missing_docs)]
#![warn(unreachable_pub)]
#![warn(rust_2018_idioms)]

pub mod error;
pub mod hash;
pub mod log;
pub mod policy;

pub use crate::error::{Error, Result};
