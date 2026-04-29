// SPDX-License-Identifier: Apache-2.0

//! The [`Event`] type, representing a single entry of an IMA event log.

#[cfg(feature = "hash")]
use crate::hash::HashAlgorithm;

use super::template::{Template, TemplateData};
use super::template_hash;

/// A single IMA measurement event.
///
/// Fields mirror the wire format described in the IMA specification:
///
/// 1. `pcr_index` — PCR that `template_hash` was extended into (conventional
///    default: `10`).
/// 2. `template_hash` — digest covering the template's data bytes, computed
///    with the algorithm recorded in
///    [`ParseOptions::template_hash_algorithm`](super::parser::ParseOptions::with_template_hash_algorithm).
/// 3. `template` — ASCII identifier of the template (`"ima"`,
///    `"ima-ng"`, `"ima-sig"`, `"ima-buf"`, …).
/// 4. `template_data` — decoded payload; see [`TemplateData`].
/// 5. `template_data_raw` — unparsed template-data bytes, retained so the
///    template hash can be recomputed even when the payload is
///    template-specific or we don't recognise the template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// PCR index. Conventional default: `10`.
    pub pcr_index: u32,

    /// Template hash as read from the log.
    pub template_hash: Vec<u8>,

    /// Template name (e.g. `"ima-ng"`).
    pub template: Template,

    /// Decoded template payload.
    pub template_data: TemplateData,

    /// Raw bytes that make up `template_data` on the wire, stored so
    /// [`calculate_template_hash`](Event::calculate_template_hash) can run
    /// without any re-encoding ambiguity.
    pub template_data_raw: Vec<u8>,
}

impl Event {
    /// Recompute the `template_hash` with the given hash algorithm, using the
    /// same rules as the Linux kernel.
    ///
    /// For the legacy `"ima"` template the hash covers `<20 bytes digest> ||
    /// <256 bytes zero-padded name>` with no length prefixes. For every
    /// other template it covers the concatenation of `<u32 LE length> ||
    /// <field data>` for each field.
    ///
    /// Returns the freshly computed digest, or `None` when `algo` has no
    /// built-in backend (MD4, MD5, RIPEMD, Whirlpool, SM3, Streebog, SHA-3,
    /// …). Callers that want to plug in their own hash implementation for
    /// such algorithms should use
    /// [`calculate_template_hash_with`](Event::calculate_template_hash_with).
    #[cfg(feature = "hash")]
    #[must_use]
    pub fn calculate_template_hash(&self, algo: HashAlgorithm) -> Option<Vec<u8>> {
        template_hash::calculate_with(self, algo)
    }

    /// Same as [`Event::calculate_template_hash`] but letting the caller
    /// supply a custom [`Hasher`](crate::hash::Hasher) instead of relying on
    /// the built-in RustCrypto backends.
    pub fn calculate_template_hash_with<H>(&self, hasher: H) -> Vec<u8>
    where
        H: crate::hash::Hasher + 'static,
    {
        template_hash::calculate_with_hasher(self, Box::new(hasher))
    }

    /// Returns `Some(true)` when the stored `template_hash` matches what a
    /// fresh computation with the given algorithm yields, `Some(false)` when
    /// they differ, and `None` when `algo` has no built-in backend so the
    /// recomputation could not run.
    #[cfg(feature = "hash")]
    #[must_use]
    pub fn verify_template_hash(&self, algo: HashAlgorithm) -> Option<bool> {
        let computed = self.calculate_template_hash(algo)?;
        Some(computed == self.template_hash)
    }
}
