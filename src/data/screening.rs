//! Security findings for the exact AUR versions offered by the update list.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::updates::{Source, Update};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Status {
    Clean,
    Flagged,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub status: Status,
    pub summary: String,
    pub findings: Vec<String>,
    pub url: String,
}

#[derive(Clone, Copy)]
struct Candidate<'a> {
    name: &'a str,
    new: &'a str,
}

fn unknown(update: &Candidate<'_>, reason: &str) -> Report {
    Report {
        version: update.new.to_string(),
        status: Status::Unknown,
        summary: reason.into(),
        findings: Vec::new(),
        url: result_url(update.name),
    }
}

fn result_url(name: &str) -> String {
    if !package_name(name) {
        return "https://wtako.net/services/aur-audit".into();
    }
    format!(
        "https://aur-audit.wtako.net/package-analysis?names={}",
        percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
    )
}

fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
        && !name.starts_with(['-', '.'])
}

fn text(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(1000)
        .collect()
}

fn report(update: &Candidate<'_>, entry: Option<&Value>) -> Report {
    let Some(entry) = entry.filter(|v| v.is_object()) else {
        return unknown(update, "WTAKO has no assessment");
    };
    if entry["packageName"].as_str() != Some(update.name) {
        return unknown(update, "WTAKO package identity does not match");
    }
    if entry["version"].as_str() != Some(update.new) || update.new.is_empty() {
        let version = entry["version"].as_str().map(text).unwrap_or_default();
        let reason = if version.is_empty() {
            "WTAKO did not identify an assessed version".into()
        } else {
            format!(
                "WTAKO assessed version {version}; update needs {}",
                text(update.new)
            )
        };
        return unknown(update, &reason);
    }
    if entry["status"].as_str() != Some("scanned") {
        return unknown(update, "WTAKO assessment is incomplete");
    }
    let mut findings = Vec::new();
    let mut severity = "";
    for (field, label) in [
        ("blackFlags", "Black"),
        ("redFlags", "Red"),
        ("yellowFlags", "Yellow"),
    ] {
        let Some(flags) = entry[field].as_array() else {
            return unknown(update, "WTAKO returned invalid findings");
        };
        if flags.len() > 100 || flags.iter().any(|f| !f.is_string()) {
            return unknown(update, "WTAKO returned invalid findings");
        }
        if !flags.is_empty() && severity.is_empty() {
            severity = label;
        }
        for flag in flags {
            let raw = flag.as_str().unwrap();
            let flag = text(raw);
            // An altered or truncated finding cannot identify persistent approval.
            if raw != flag {
                return unknown(update, "WTAKO findings exceed display bounds");
            }
            if flag.trim().is_empty() {
                return unknown(update, "WTAKO returned empty findings");
            }
            findings.push(format!("{label}: {flag}"));
        }
    }
    Report {
        version: update.new.to_string(),
        status: if findings.is_empty() {
            Status::Clean
        } else {
            Status::Flagged
        },
        summary: if findings.is_empty() {
            "WTAKO: no findings".into()
        } else {
            format!("WTAKO: {severity} ({})", findings.len())
        },
        findings,
        url: result_url(update.name),
    }
}

fn rejected() -> crate::script::Failure {
    crate::script::Failure::classify(crate::script::op::UPGRADE_RUN, Some(14), None, Vec::new())
}

fn fetch(names: &str) -> Result<Value, crate::script::Failure> {
    let response = crate::script::query(crate::script::op::UPGRADE_AUDIT, &[names])?;
    if response.len() > 4 * 1024 * 1024 {
        return Err(rejected());
    }
    serde_json::from_str(&response).map_err(|_| rejected())
}

fn candidates(
    updates: &[Candidate<'_>],
) -> Result<BTreeMap<String, Report>, crate::script::Failure> {
    candidates_with(updates, fetch)
}

fn candidates_with(
    updates: &[Candidate<'_>],
    mut fetch: impl FnMut(&str) -> Result<Value, crate::script::Failure>,
) -> Result<BTreeMap<String, Report>, crate::script::Failure> {
    let mut results: BTreeMap<_, _> = updates
        .iter()
        .map(|u| {
            (
                u.name.to_string(),
                unknown(u, "WTAKO assessment unavailable"),
            )
        })
        .collect();
    let valid: Vec<_> = updates.iter().filter(|u| package_name(u.name)).collect();
    let mut remaining = valid.as_slice();
    for _ in 0..20 {
        if remaining.is_empty() {
            break;
        }
        let mut bytes = 0;
        let count = remaining
            .iter()
            .take(100)
            .take_while(|u| {
                bytes += u.name.len() + 1;
                bytes <= 1800
            })
            .count();
        let (batch, rest) = remaining.split_at(count);
        remaining = rest;
        let names = batch.iter().map(|u| u.name).collect::<Vec<_>>().join(",");
        let Ok(response) = fetch(&names) else {
            continue;
        };
        let packages = response["packages"].as_object().ok_or_else(rejected)?;
        for update in batch {
            results.insert(
                update.name.to_string(),
                report(update, packages.get(update.name)),
            );
        }
    }
    if !remaining.is_empty() {
        return Err(rejected());
    }
    Ok(results)
}

/// Failed lookups, absent packages and mismatched versions remain unknown. The
/// provider identifies package bases, so an unresolved split package is unknown.
/// At most 20 batches allow 100 names and 1,800 name bytes each (URLs under 6 KiB).
pub fn lookup(updates: &[Update]) -> BTreeMap<String, Report> {
    let aur: Vec<_> = updates
        .iter()
        .filter(|u| u.source == Source::Aur)
        .map(|u| Candidate {
            name: &u.name,
            new: &u.new,
        })
        .collect();
    candidates(&aur).unwrap_or_else(|_| {
        aur.iter()
            .map(|u| {
                (
                    u.name.to_string(),
                    unknown(u, "WTAKO assessment unavailable"),
                )
            })
            .collect()
    })
}

fn arguments(
    expected: &BTreeMap<String, Report>,
    fresh: &BTreeMap<String, Report>,
    state: &crate::state::State,
    packages: &[super::aur::Package],
) -> Result<Vec<String>, crate::script::Failure> {
    if expected.is_empty() || expected != fresh {
        return Err(rejected());
    }
    let mut args = vec!["screened".into()];
    for (name, report) in expected {
        let mut found = packages.iter().filter(|p| &p.name == name);
        let package = found.next().ok_or_else(rejected)?;
        if found.next().is_some()
            || !package_name(name)
            || !package_name(&package.package_base)
            || package.version != report.version
            || report.version.is_empty()
            || report.version.len() > 200
            || report
                .version
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || state.aur_holds.contains_key(name)
            || (report.status != Status::Clean && state.aur_trust.get(name) != Some(report))
        {
            return Err(rejected());
        }
        args.extend([
            name.clone(),
            report.version.clone(),
            package.package_base.clone(),
        ]);
    }
    Ok(args)
}

/// Recheck the selected evidence and decisions immediately before executing the
/// versioned package targets. Every mismatch requires the user to refresh.
pub fn verify(expected: &BTreeMap<String, Report>) -> Result<Vec<String>, crate::script::Failure> {
    let selected: Vec<_> = expected
        .iter()
        .map(|(name, r)| Candidate {
            name,
            new: &r.version,
        })
        .collect();
    if selected.is_empty() || selected.iter().any(|u| !package_name(u.name)) {
        return Err(rejected());
    }
    let fresh = candidates(&selected)?;
    if &fresh != expected {
        crate::state::State::try_update(|state| {
            state.aur_trust.retain(|name, approved| {
                expected.get(name) != Some(approved) || fresh.get(name) == Some(approved)
            });
        })
        .map_err(|_| rejected())?;
        return Err(rejected());
    }
    let mut packages = Vec::new();
    for batch in selected.chunks(8) {
        let args: Vec<_> = batch.iter().map(|u| u.name).collect();
        let out = crate::script::query(crate::script::op::PACKAGES_AUR_INFO, &args)?;
        if out.len() > 4 * 1024 * 1024 {
            return Err(rejected());
        }
        packages.extend(super::aur::parse(&out).map_err(|_| rejected())?);
    }
    let state = crate::state::State::try_load().map_err(|_| rejected())?;
    arguments(expected, &fresh, &state, &packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn update() -> Candidate<'static> {
        Candidate {
            name: "paru",
            new: "2.2.0-1",
        }
    }

    fn assessment() -> Value {
        json!({"packageName":"paru","status":"scanned","version":"2.2.0-1",
            "analysisOn":1794959441512_i64,"blackFlags":[],"redFlags":[],"yellowFlags":[]})
    }

    #[test]
    fn outage_requires_exact_unknown_approval_and_preserves_completed_batches() {
        let clean = BTreeMap::from([("paru".into(), report(&update(), Some(&assessment())))]);
        let unavailable = candidates_with(&[update()], |_| Err(rejected())).unwrap();
        assert_eq!(unavailable["paru"].summary, "WTAKO assessment unavailable");
        let packages = super::super::aur::parse(r#"{"type":"multiinfo","results":[{"Name":"paru","PackageBase":"paru","Version":"2.2.0-1"}]}"#).unwrap();
        let mut state = crate::state::State::default();
        assert!(arguments(&clean, &unavailable, &state, &packages).is_err());
        assert!(arguments(&unavailable, &unavailable, &state, &packages).is_err());
        state.aur_trust = unavailable.clone();
        assert!(arguments(&unavailable, &unavailable, &state, &packages).is_ok());
        state.aur_trust = clean;
        assert!(arguments(&unavailable, &unavailable, &state, &packages).is_err());

        let names: Vec<_> = (0..101).map(|n| format!("pkg{n}")).collect();
        let updates: Vec<_> = names
            .iter()
            .map(|n| Candidate {
                name: n,
                new: "2.2.0-1",
            })
            .collect();
        let mut calls = 0;
        let results = candidates_with(&updates, |_| {
            calls += 1;
            if calls == 2 {
                return Err(rejected());
            }
            let mut r = assessment();
            r["packageName"] = json!("pkg0");
            Ok(json!({"packages":{"pkg0":r}}))
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(results["pkg0"].status, Status::Clean);
        assert_eq!(results["pkg100"].summary, "WTAKO assessment unavailable");
    }

    #[test]
    fn verification_requires_current_evidence_policy_and_exact_rpc_identity() {
        let r = report(&update(), Some(&assessment()));
        let expected = BTreeMap::from([("paru".into(), r.clone())]);
        let packages = super::super::aur::parse(r#"{"type":"multiinfo","results":[{"Name":"paru","PackageBase":"paru-base","Version":"2.2.0-1"}]}"#).unwrap();
        let mut state = crate::state::State::default();
        assert_eq!(
            arguments(&expected, &expected, &state, &packages).unwrap(),
            ["screened", "paru", "2.2.0-1", "paru-base"]
        );
        assert!(arguments(&expected, &expected, &state, &[]).is_err());
        let mut wrong = packages.clone();
        wrong[0].version = "2.3.0-1".into();
        assert!(arguments(&expected, &expected, &state, &wrong).is_err());
        wrong[0] = packages[0].clone();
        wrong[0].package_base = "foo/bar".into();
        assert!(arguments(&expected, &expected, &state, &wrong).is_err());
        state.aur_holds.insert("paru".into(), "2.2.0-1".into());
        assert!(arguments(&expected, &expected, &state, &packages).is_err());
        state.aur_holds.clear();
        for status in [Status::Flagged, Status::Unknown] {
            let mut changed = expected.clone();
            changed.get_mut("paru").unwrap().status = status;
            assert!(arguments(&changed, &changed, &state, &packages).is_err());
            state.aur_trust = changed.clone();
            assert!(arguments(&changed, &changed, &state, &packages).is_ok());
            let mut fresh = changed.clone();
            fresh
                .get_mut("paru")
                .unwrap()
                .findings
                .push("New evidence".into());
            assert!(arguments(&changed, &fresh, &state, &packages).is_err());
            state.aur_trust.clear();
            assert!(arguments(&changed, &changed, &state, &packages).is_err());
        }
    }

    #[test]
    fn requires_identity_version_and_complete_assessment() {
        let u = update();
        let entry = assessment();
        assert_eq!(report(&u, Some(&entry)).status, Status::Clean);
        assert_eq!(report(&u, None).status, Status::Unknown);
        for (key, value) in [
            ("version", json!("2.1.0-1")),
            ("packageName", json!("other")),
            ("status", json!("scanning")),
            ("yellowFlags", Value::Null),
            ("redFlags", json!([1])),
            ("blackFlags", json!(["\u{001b}\n"])),
        ] {
            let mut invalid = entry.clone();
            invalid[key] = value;
            assert_eq!(report(&u, Some(&invalid)).status, Status::Unknown, "{key}");
        }
    }

    #[test]
    fn preserves_severity_and_rejects_ambiguous_display_evidence() {
        let mut entry = assessment();
        entry["redFlags"] = json!(["Payload detected"]);
        entry["yellowFlags"] = json!(["Network download"]);
        let r = report(&update(), Some(&entry));
        assert_eq!(r.status, Status::Flagged);
        assert_eq!(r.summary, "WTAKO: Red (2)");
        assert_eq!(
            r.findings,
            ["Red: Payload detected", "Yellow: Network download"]
        );
        for flag in [
            "\u{001b}[31mPayload\n\u{202e}".to_string(),
            "x".repeat(1001),
        ] {
            entry["redFlags"] = json!([flag]);
            assert_eq!(report(&update(), Some(&entry)).status, Status::Unknown);
        }
    }

    #[test]
    fn stale_reports_identify_the_assessed_and_requested_versions() {
        let mut old = assessment();
        old["version"] = json!("1.0-1");
        let stale = report(&update(), Some(&old));
        assert!(stale.summary.contains("1.0-1"));
        assert!(stale.summary.contains("2.2.0-1"));
        assert!(stale.url.contains("?names=paru"));
    }

    #[test]
    fn package_names_cannot_inject_query_parameters() {
        assert!(package_name("libfoo++-git"));
        assert_eq!(
            result_url("libfoo++-git"),
            "https://aur-audit.wtako.net/package-analysis?names=libfoo%2B%2B%2Dgit"
        );
        for name in ["", "foo&names=bar", "foo,bar", "../foo", "-foo", "foo\n"] {
            assert!(!package_name(name));
        }
    }
}
