// SPDX-License-Identifier: Apache-2.0

//! Parser for the IMA policy syntax.
//!
//! The grammar follows `Documentation/ABI/testing/ima_policy` from the
//! Linux kernel. Numeric identity conditions (`uid`, `euid`, `gid`, `egid`,
//! `fowner`, `fgroup`) accept the three operator forms `=`, `<` and `>` as
//! the kernel's `ima_policy.c` does.

use crate::error::{Error, Result};

use super::rule::{
    Action, AppraiseAlgo, AppraiseFlag, AppraiseType, Condition, DigestType, Func, IdOp,
    LabelEntry, Mask, MaskBit, Opt, Policy, Rule, Template,
};

/// Parse a complete IMA policy.
///
/// Lines that are blank or begin with `#` are skipped. All other lines must
/// be valid rules; any parse error aborts and is reported with the
/// offending line number.
pub fn parse_policy(input: &str) -> Result<Policy> {
    let mut rules = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        rules.push(
            parse_policy_line(line).map_err(|e| Error::parse(format!("line {}: {}", i + 1, e)))?,
        );
    }
    Ok(Policy { rules })
}

/// Parse a single policy rule from a single line.
pub fn parse_policy_line(line: &str) -> Result<Rule> {
    let mut tokens = line.split_whitespace();
    let action_str = tokens
        .next()
        .ok_or_else(|| Error::malformed("empty rule"))?;
    let action = Action::parse(action_str)
        .ok_or_else(|| Error::malformed(format!("unknown action `{action_str}`")))?;

    let mut conditions = Vec::new();
    let mut options = Vec::new();

    for tok in tokens {
        if let Some((key, op, value)) = split_key_op_value(tok) {
            match parse_keyed(key, op, value)? {
                Parsed::Condition(c) => conditions.push(c),
                Parsed::Option(o) => options.push(o),
            }
        } else {
            // Bare flags are always options in the IMA grammar.
            options.push(match tok {
                "permit_directio" => Opt::PermitDirectio,
                other => Opt::Flag(other.to_owned()),
            });
        }
    }

    Ok(Rule {
        action,
        conditions,
        options,
    })
}

enum Parsed {
    Condition(Condition),
    Option(Opt),
}

/// Split a token like `uid=1000` / `uid<1000` / `uid>1000` into
/// `(key, op_char, value)`. Returns `None` when the token contains no
/// recognised operator at all (a bare flag).
fn split_key_op_value(tok: &str) -> Option<(&str, char, &str)> {
    // The kernel only recognises the operators on numeric identity
    // conditions, but lexically every keyed token uses one of `= < >`.
    // Find the first occurrence of any of them.
    tok.char_indices()
        .find(|(_, c)| matches!(c, '=' | '<' | '>'))
        .map(|(i, c)| (&tok[..i], c, &tok[i + c.len_utf8()..]))
}

fn parse_keyed(key: &str, op: char, value: &str) -> Result<Parsed> {
    // Identity-style conditions accept `=`, `<`, `>`. Everything else
    // must use plain `=`.
    let id_op = match op {
        '=' => IdOp::Eq,
        '<' => IdOp::Lt,
        '>' => IdOp::Gt,
        _ => unreachable!(),
    };

    if matches!(key, "uid" | "euid" | "gid" | "egid" | "fowner" | "fgroup") {
        let value = parse_dec_u32(value)?;
        let cond = match key {
            "uid" => Condition::Uid { op: id_op, value },
            "euid" => Condition::Euid { op: id_op, value },
            "gid" => Condition::Gid { op: id_op, value },
            "egid" => Condition::Egid { op: id_op, value },
            "fowner" => Condition::Fowner { op: id_op, value },
            "fgroup" => Condition::Fgroup { op: id_op, value },
            _ => unreachable!(),
        };
        return Ok(Parsed::Condition(cond));
    }

    // For every other keyword the only legal operator is `=`.
    if op != '=' {
        return Err(Error::malformed(format!(
            "operator `{op}` is only valid on uid/euid/gid/egid/fowner/fgroup, not `{key}`"
        )));
    }

    Ok(match key {
        // --- Conditions -------------------------------------------------
        "func" => Parsed::Condition(Condition::Func(Func::parse(value))),
        "mask" => Parsed::Condition(Condition::Mask(parse_mask(value)?)),
        "fsmagic" => Parsed::Condition(Condition::Fsmagic(parse_hex_u64(value)?)),
        "fsuuid" => Parsed::Condition(Condition::Fsuuid(value.to_owned())),
        "fsname" => Parsed::Condition(Condition::Fsname(value.to_owned())),
        "fs_subtype" => Parsed::Condition(Condition::FsSubtype(value.to_owned())),
        "subj_user" => Parsed::Condition(Condition::SubjUser(value.to_owned())),
        "subj_role" => Parsed::Condition(Condition::SubjRole(value.to_owned())),
        "subj_type" => Parsed::Condition(Condition::SubjType(value.to_owned())),
        "obj_user" => Parsed::Condition(Condition::ObjUser(value.to_owned())),
        "obj_role" => Parsed::Condition(Condition::ObjRole(value.to_owned())),
        "obj_type" => Parsed::Condition(Condition::ObjType(value.to_owned())),

        // --- Options ---------------------------------------------------
        "digest_type" => Parsed::Option(Opt::DigestType(DigestType::parse(value))),
        "template" => Parsed::Option(Opt::Template(Template::parse(value))),
        "appraise_type" => Parsed::Option(Opt::AppraiseType(AppraiseType::parse(value))),
        "appraise_flag" => Parsed::Option(Opt::AppraiseFlag(AppraiseFlag::parse(value))),
        "appraise_algos" => Parsed::Option(Opt::AppraiseAlgos(parse_appraise_algos(value)?)),
        "keyrings" => Parsed::Option(Opt::Keyrings(parse_pipe_list(value, "keyrings")?)),
        "label" => {
            let entries = parse_pipe_list(value, "label")?
                .into_iter()
                .map(|s| LabelEntry::parse(&s))
                .collect();
            Parsed::Option(Opt::Label(entries))
        }
        "pcr" => Parsed::Option(Opt::Pcr(parse_dec_u32(value)?)),

        other => Parsed::Option(Opt::Other {
            key: other.to_owned(),
            value: value.to_owned(),
        }),
    })
}

fn parse_mask(value: &str) -> Result<Mask> {
    let (negated, name) = match value.strip_prefix('^') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let bit = MaskBit::parse(name)
        .ok_or_else(|| Error::malformed(format!("unknown mask bit `{name}`")))?;
    Ok(Mask { negated, bit })
}

fn parse_appraise_algos(value: &str) -> Result<Vec<AppraiseAlgo>> {
    if value.is_empty() {
        return Err(Error::malformed("empty appraise_algos list"));
    }
    let parts: Vec<&str> = value.split(',').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(Error::malformed(format!(
            "empty entry in appraise_algos `{value}`"
        )));
    }
    Ok(parts.into_iter().map(AppraiseAlgo::parse).collect())
}

fn parse_pipe_list(value: &str, what: &'static str) -> Result<Vec<String>> {
    if value.is_empty() {
        return Err(Error::malformed(format!("empty {what} list")));
    }
    let parts: Vec<&str> = value.split('|').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(Error::malformed(format!("empty entry in {what} `{value}`")));
    }
    Ok(parts.into_iter().map(str::to_owned).collect())
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let clean = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(clean, 16)
        .map_err(|_| Error::malformed(format!("invalid fsmagic value `{s}`")))
}

fn parse_dec_u32(s: &str) -> Result<u32> {
    s.parse::<u32>()
        .map_err(|_| Error::malformed(format!("invalid integer `{s}`")))
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashAlgorithm;

    #[test]
    fn parses_simple_measure_rule() {
        let r = parse_policy_line("measure func=BPRM_CHECK").unwrap();
        assert_eq!(r.action, Action::Measure);
        assert_eq!(r.conditions, vec![Condition::Func(Func::BprmCheck)]);
    }

    #[test]
    fn parses_mask_with_negation() {
        let r = parse_policy_line("measure func=FILE_CHECK mask=^MAY_READ").unwrap();
        match &r.conditions[1] {
            Condition::Mask(m) => {
                assert!(m.negated);
                assert_eq!(m.bit, MaskBit::MayRead);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_mask_bit() {
        let err = parse_policy_line("measure func=FILE_CHECK mask=hogehoge").unwrap_err();
        assert!(err.to_string().contains("unknown mask bit"));
    }

    #[test]
    fn parses_fsmagic_and_uid() {
        let r = parse_policy_line("dont_measure fsmagic=0x9fa0 uid=1000").unwrap();
        assert_eq!(r.action, Action::DontMeasure);
        assert!(r.conditions.contains(&Condition::Fsmagic(0x9fa0)));
        assert!(r.conditions.contains(&Condition::Uid {
            op: IdOp::Eq,
            value: 1000,
        }));
    }

    #[test]
    fn parses_id_operator_lt_gt() {
        let r = parse_policy_line("measure uid<1000 fowner>0").unwrap();
        assert!(r.conditions.contains(&Condition::Uid {
            op: IdOp::Lt,
            value: 1000,
        }));
        assert!(r.conditions.contains(&Condition::Fowner {
            op: IdOp::Gt,
            value: 0,
        }));
    }

    #[test]
    fn rejects_lt_gt_on_non_id_keys() {
        let err = parse_policy_line("measure func<BPRM_CHECK").unwrap_err();
        assert!(err.to_string().contains("only valid"));
    }

    #[test]
    fn parses_appraise_type() {
        let r = parse_policy_line("appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig|modsig")
            .unwrap();
        assert_eq!(r.action, Action::Appraise);
        let opt = r.options.first().unwrap();
        match opt {
            Opt::AppraiseType(t) => assert_eq!(*t, AppraiseType::ImasigModsig),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_sigv3_appraise_type() {
        let r = parse_policy_line("appraise func=BPRM_CHECK appraise_type=sigv3").unwrap();
        assert!(r.options.contains(&Opt::AppraiseType(AppraiseType::Sigv3)));
    }

    #[test]
    fn parses_digest_type_verity_and_template() {
        let r = parse_policy_line("measure func=FILE_CHECK digest_type=verity template=ima-ngv2")
            .unwrap();
        assert!(r.options.contains(&Opt::DigestType(DigestType::Verity)));
        assert!(r.options.contains(&Opt::Template(Template::ImaNgv2)));
    }

    #[test]
    fn parses_permit_directio_flag() {
        let r = parse_policy_line("measure func=FILE_CHECK permit_directio").unwrap();
        assert!(r.options.contains(&Opt::PermitDirectio));
    }

    #[test]
    fn parses_appraise_algos_list() {
        let r =
            parse_policy_line("appraise func=SETXATTR_CHECK appraise_algos=sha256,sha384,sha512")
                .unwrap();
        match r.options.last().unwrap() {
            Opt::AppraiseAlgos(algos) => {
                assert_eq!(algos.len(), 3);
                assert_eq!(algos[0], AppraiseAlgo::Algorithm(HashAlgorithm::Sha256));
                assert_eq!(algos[1], AppraiseAlgo::Algorithm(HashAlgorithm::Sha384));
                assert_eq!(algos[2], AppraiseAlgo::Algorithm(HashAlgorithm::Sha512));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_keyrings_pipe_list() {
        let r = parse_policy_line("measure func=KEY_CHECK keyrings=.builtin_trusted_keys|.ima")
            .unwrap();
        match r.options.last().unwrap() {
            Opt::Keyrings(k) => {
                assert_eq!(
                    k,
                    &vec![".builtin_trusted_keys".to_owned(), ".ima".to_owned()]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_label_pipe_list_with_known_and_custom() {
        let r = parse_policy_line("measure func=CRITICAL_DATA label=selinux|kernel_info|my_label")
            .unwrap();
        match r.options.last().unwrap() {
            Opt::Label(entries) => {
                assert_eq!(
                    entries,
                    &vec![
                        LabelEntry::Selinux,
                        LabelEntry::KernelInfo,
                        LabelEntry::Custom("my_label".to_owned()),
                    ]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_pcr_as_option() {
        let r = parse_policy_line("measure func=KEXEC_KERNEL_CHECK pcr=4").unwrap();
        assert!(r.options.contains(&Opt::Pcr(4)));
    }

    #[test]
    fn parses_file_mmap_alias_to_mmap_check() {
        let r = parse_policy_line("measure func=FILE_MMAP mask=MAY_EXEC").unwrap();
        assert_eq!(r.conditions[0], Condition::Func(Func::MmapCheck));
    }

    #[test]
    fn parses_path_check_alias_to_file_check() {
        let r = parse_policy_line("measure func=PATH_CHECK").unwrap();
        assert_eq!(r.conditions[0], Condition::Func(Func::FileCheck));
    }

    #[test]
    fn unknown_func_falls_back_to_other() {
        let r = parse_policy_line("measure func=FUTURE_CHECK").unwrap();
        match &r.conditions[0] {
            Condition::Func(Func::Other(s)) => assert_eq!(s, "FUTURE_CHECK"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ignores_comments_and_blanks() {
        let text = "\
# ignore me\n\
\n\
measure func=BPRM_CHECK\n\
dont_measure fsmagic=0x9fa0 uid=0 # trailing comment\n\
";
        let p = parse_policy(text).unwrap();
        assert_eq!(p.rules.len(), 2);
    }
}
