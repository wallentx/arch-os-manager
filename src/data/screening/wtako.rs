//! WTAKO returns the most recent report by name, which may describe an older version.

use super::{Category, Evidence, Scanner};
use serde_json::Value;
use std::collections::BTreeMap;

fn report(name: &str, entry: Option<&Value>) -> Evidence {
    let mut evidence = Evidence {
        scanner: Scanner::Wtako,
        version: None,
        category: Category::Missing,
        summary: "No WTAKO assessment available".into(),
        findings: Vec::new(),
        url: format!(
            "https://aur-audit.wtako.net/package-analysis?names={}",
            percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
        ),
    };
    let Some(e) =
        entry.filter(|e| e["packageName"].as_str() == Some(name) && e["status"] == "scanned")
    else {
        return evidence;
    };
    let clean_text = |v: &str| {
        !v.trim().is_empty()
            && v.len() <= 2000
            && !v.chars().any(|c| {
                c.is_control() || matches!(c,'\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
    };
    evidence.version = e["version"]
        .as_str()
        .filter(|v| clean_text(v))
        .map(str::to_owned);
    let mut findings = Vec::new();
    let mut complete = true;
    let mut category = Category::Clean;
    for (field, label, outcome) in [
        ("blackFlags", "Black", Category::Malicious),
        ("redFlags", "Red", Category::Suspicious),
        ("yellowFlags", "Yellow", Category::Minor),
    ] {
        let Some(flags) = e[field].as_array() else {
            complete = false;
            continue;
        };
        if flags.len() > 100 {
            complete = false;
            if outcome == Category::Malicious
                && flags
                    .iter()
                    .any(|v| v.as_str().is_some_and(|v| !v.trim().is_empty()))
            {
                category = Category::Malicious;
            }
            continue;
        }
        for item in flags {
            let Some(text) = item.as_str().filter(|s| clean_text(s)) else {
                complete = false;
                if outcome == Category::Malicious
                    && item.as_str().is_some_and(|v| !v.trim().is_empty())
                {
                    category = Category::Malicious;
                }
                continue;
            };
            findings.push(format!("{label}: {text}"));
            if category == Category::Clean {
                category = outcome;
            }
        }
    }
    if !complete && category != Category::Malicious {
        evidence.summary = "Incomplete WTAKO assessment".into();
        return evidence;
    }
    if !complete {
        findings.push("Additional finding details unavailable".into());
    }
    evidence.summary = match category {
        Category::Malicious => "Black flag",
        Category::Suspicious => "Red flag",
        Category::Minor => "Yellow flag",
        _ => "No flags",
    }
    .into();
    evidence.findings = findings;
    evidence.category = category;
    evidence
}

pub(super) fn lookup(packages: &[(String, String)]) -> BTreeMap<String, Evidence> {
    let mut results = BTreeMap::new();
    let mut remaining = packages;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(16);
    for _ in 0..20 {
        if remaining.is_empty() || std::time::Instant::now() >= deadline {
            break;
        }
        let mut bytes = 0;
        let count = remaining
            .iter()
            .take(100)
            .take_while(|(name, _)| {
                bytes += name.len() + 1;
                bytes <= 1800
            })
            .count();
        let (batch, rest) = remaining.split_at(count);
        remaining = rest;
        let names = batch
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let response = crate::script::query(crate::script::op::UPGRADE_AUDIT, &[&names])
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        for (name, _) in batch {
            results.insert(
                name.clone(),
                report(
                    name,
                    response.as_ref().and_then(|v| v["packages"].get(name)),
                ),
            );
        }
    }
    for (name, _) in remaining {
        results.insert(name.clone(), report(name, None));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn preserves_versions_flags_and_uncertainty() {
        let mut item = json!({"status":"scanned","packageName":"example","version":"1-1","blackFlags":[],"redFlags":[],"yellowFlags":[]});
        for (field, cat) in [
            ("yellowFlags", Category::Minor),
            ("redFlags", Category::Suspicious),
            ("blackFlags", Category::Malicious),
        ] {
            item[field] = json!(["finding"]);
            let got = report("example", Some(&item));
            assert_eq!(got.version.as_deref(), Some("1-1"));
            assert_eq!(got.category, cat);
            assert!(!got.findings.is_empty());
        }
        item["blackFlags"] = json!(["escape\u{001b}"]);
        assert_eq!(report("example", Some(&item)).category, Category::Malicious);
        item["blackFlags"] = Value::Null;
        assert_eq!(report("example", Some(&item)).category, Category::Missing);
        assert_eq!(report("different", Some(&item)).category, Category::Missing);
    }
}
