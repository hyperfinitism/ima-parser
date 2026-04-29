// SPDX-License-Identifier: Apache-2.0

//! IMA event log (a.k.a. *measurement list* / *integrity log*).
//!
//! The Linux kernel exposes the event log through `securityfs`:
//!
//! * `/sys/kernel/security/ima/binary_runtime_measurements[_<algo>]` – the
//!   packed binary representation parsed by [`EventLogParser`].
//! * `/sys/kernel/security/ima/ascii_runtime_measurements[_<algo>]` – a
//!   human-readable, space-separated rendering parsed by [`parse_ascii_log`].
//!
//! Both parsers produce the same [`Event`] type, so applications can mix and
//! match representations freely. The [`template_hash`] of every event can be
//! recomputed with [`Event::calculate_template_hash`] to verify the log's
//! self-consistency, independently of any TPM replay.
//!
//! [`template_hash`]: Event::template_hash

mod ascii;
mod event;
mod parser;
mod template;
mod template_hash;

pub use self::ascii::{parse_ascii_line, parse_ascii_log};
pub use self::event::Event;
pub use self::parser::{Endianness, EventLogParser, ParseOptions};
pub use self::template::{
    Digest, DigestType, DigestV2, EvmSigEntry, ImaBufEntry, ImaEntry, ImaModsigEntry, ImaNgEntry,
    ImaNgV2Entry, ImaSigEntry, ImaSigV2Entry, Template, TemplateData, TemplateField,
    TemplateFieldId,
};

/// Default PCR index used by IMA (`CONFIG_IMA_MEASURE_PCR_IDX`).
pub const DEFAULT_IMA_PCR: u32 = 10;

/// Maximum length of an `n` (legacy) filename field, excluding the nul byte.
/// The legacy `ima` template pads the `n` field to this size plus one when
/// computing the template hash.
pub const IMA_EVENT_NAME_LEN_MAX: usize = 255;
