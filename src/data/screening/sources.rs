//! Public scan reports with provider-specific identities, verdicts and report links.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{Category, Evidence, Scanner};

mod pages;
mod sleuth;

// A slow or incomplete service cannot keep a refresh busy indefinitely.
const BUDGET: Duration = Duration::from_secs(16);

fn fetch(args: &[&str]) -> Option<String> {
    crate::script::query(crate::script::op::UPGRADE_SCAN, args).ok()
}

fn url(scanner: Scanner, name: &str) -> String {
    let name = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    match scanner {
        Scanner::Aurwatch => format!("https://aurwatch.org/package/{name}"),
        Scanner::Pkglint => format!("https://jamison.lahman.dev/pkglint/package/{name}.html"),
        Scanner::AurReview => format!("https://aur-review.com/?search={name}"),
        Scanner::AurSleuth => format!("https://mgalgs.io/aur-sleuth/#pkg={name}"),
        Scanner::Cretezy => format!("https://aur-security.cretezy.com/checks?q={name}"),
        Scanner::Wtako => format!("https://aur-audit.wtako.net/package-analysis?names={name}"),
    }
}

fn missing(scanner: Scanner, name: &str, reason: &str) -> Evidence {
    Evidence {
        scanner,
        version: None,
        category: Category::Missing,
        summary: reason.into(),
        findings: Vec::new(),
        url: url(scanner, name),
    }
}

/// Normalize layout whitespace in reports without displaying terminal control sequences.
fn plain(raw: &str) -> Option<String> {
    if raw.len() > 4096 || raw.chars().any(|c| {
        (c.is_control() && !matches!(c, ' ' | '\t' | '\n' | '\r'))
            || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }) {
        return None;
    }
    let text = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    (!text.is_empty()).then_some(text)
}

fn field(value: &Value, key: &str) -> Option<String> {
    plain(value.get(key)?.as_str()?)
}

fn watch(doc: &str, name: &str) -> Option<Evidence> {
    let record: Value = serde_json::from_str(doc).ok()?;
    if record["pkg"].as_str()? != name {
        return None;
    }
    let severity = record["status"].as_str()?;
    let category = match severity {
        "clean" => Category::Clean,
        "low" => Category::Minor,
        "medium" | "high" => Category::Suspicious,
        _ => return None,
    };
    let rules = record["rules"].as_array()?;
    if (severity == "clean") != rules.is_empty() {
        return None;
    }
    let mut findings = Vec::new();
    for rule in rules {
        findings.push(format!(
            "{} [{}]: {}",
            field(rule, "name")?,
            field(rule, "severity")?,
            field(rule, "message")?
        ));
        for hit in rule["matches"].as_array()? {
            findings.push(format!(
                "{}:{}: {}",
                field(hit, "file")?,
                hit["line"].as_u64()?,
                field(hit, "text")?
            ));
        }
    }
    Some(Evidence {
        scanner: Scanner::Aurwatch,
        version: None,
        category,
        summary: format!("{severity} · scanned {}", field(&record, "last_scanned")?),
        findings,
        url: url(Scanner::Aurwatch, name),
    })
}

fn one(scanner: Scanner, name: &str, candidate: &str, deadline: Instant) -> Evidence {
    let fallback = |why| missing(scanner, name, why);
    if !super::package_name(name) {
        return fallback("Invalid package name");
    }
    let Some(response) = fetch(&[scanner.id(), name]) else {
        return fallback("No report returned (service unavailable or package not covered)");
    };
    let report = match scanner {
        Scanner::Aurwatch => watch(&response, name),
        Scanner::Pkglint => pages::lint(&response, name),
        Scanner::AurReview => pages::ai(&response, name, candidate, deadline),
        Scanner::Cretezy => pages::cretezy(&response, name, candidate, deadline),
        _ => None,
    };
    report
        .filter(|r| {
            r.findings.len() <= 128 && r.findings.iter().map(String::len).sum::<usize>() <= 65536
        })
        .unwrap_or_else(|| fallback("No readable assessment for this package"))
}

pub(super) fn lookup(scanner: Scanner, updates: &[(String, String)]) -> BTreeMap<String, Evidence> {
    if updates.is_empty() {
        return BTreeMap::new();
    }
    if scanner == Scanner::AurSleuth {
        return sleuth::lookup(updates);
    }
    let deadline = Instant::now() + BUDGET;
    let next = AtomicUsize::new(0);
    let mut reports = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..updates.len().min(2))
            .map(|_| {
                scope.spawn(|| {
                    let mut entries = Vec::new();
                    while Instant::now() < deadline {
                        let Some((name, candidate)) =
                            updates.get(next.fetch_add(1, Ordering::Relaxed))
                        else {
                            break;
                        };
                        entries.push((name.clone(), one(scanner, name, candidate, deadline)));
                    }
                    entries
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().unwrap_or_default())
            .collect::<BTreeMap<_, _>>()
    });
    for (name, _) in updates {
        reports
            .entry(name.clone())
            .or_insert_with(|| missing(scanner, name, "Source lookup timed out"));
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_preserves_unversioned_rule_matches_and_rejects_mismatched_records() {
        let body = r#"{"pkg":"pkg","status":"medium","last_scanned":"2026-11-18","rules":[{"name":"Permission","severity":"medium","message":"Check setgid","matches":[{"file":".install","line":17,"text":"chmod g+s file"}]}]}"#;
        let e = watch(body, "pkg").unwrap();
        assert_eq!(e.category, Category::Suspicious);
        assert!(e.version.is_none());
        assert_eq!(e.findings[1], ".install:17: chmod g+s file");
        assert!(watch(body, "otherpkg").is_none());
        assert!(watch(&body.replace("medium", "clean"), "pkg").is_none());
        assert!(plain("\u{1b}[1m unsafe").is_none());
    }
}
