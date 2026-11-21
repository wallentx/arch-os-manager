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
        details: Some(Vec::new()),
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

fn watch(doc: &str, name: &str, candidate: &str) -> Option<Evidence> {
    let record: Value = serde_json::from_str(doc).ok()?;
    // Today's public API normally omits the assessed version. The scan time and
    // the package name alone cannot identify the recipe it assessed.
    if record["pkg"].as_str()? != name || record["scanned_version"].as_str()? != candidate {
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
        details: Some(Vec::new()),
        scanner: Scanner::Aurwatch,
        version: Some(candidate.into()),
        category,
        summary: format!("{severity} · scanned {}", field(&record, "last_scanned")?),
        findings,
        url: url(Scanner::Aurwatch, name),
    })
}

fn one(
    scanner: Scanner,
    name: &str,
    candidate: &str,
    deadline: Instant,
    sleuth_entry: Option<&Value>,
) -> Evidence {
    let fallback = |why| missing(scanner, name, why);
    if !super::package_name(name) {
        return fallback("Invalid package name");
    }
    let response = if scanner == Scanner::AurSleuth {
        fetch(&[scanner.id(), name, "reports"])
    } else {
        fetch(&[scanner.id(), name])
    };
    let Some(response) = response else {
        return fallback("No report returned (service unavailable or package not covered)");
    };
    let report = match scanner {
        Scanner::AurSleuth => sleuth::report(name, candidate, &response, sleuth_entry),
        Scanner::Aurwatch => watch(&response, name, candidate),
        Scanner::Pkglint => pages::lint(&response, name, candidate),
        Scanner::AurReview => pages::ai(&response, name, candidate, deadline),
        Scanner::Cretezy => pages::cretezy(&response, name, candidate, deadline),
        _ => None,
    };
    report
        .map(|mut r| {
            // Keep the published verdict when its optional explanation exceeds the display limits.
            if r.details.as_ref().is_some_and(|details| {
                details.len() > 128 || details.iter().map(String::len).sum::<usize>() > 65536
            }) {
                r.details = None;
            }
            r
        })
        .filter(|r| {
            r.findings.len() <= 128 && r.findings.iter().map(String::len).sum::<usize>() <= 65536
        })
        .unwrap_or_else(|| fallback("No readable assessment for this package"))
}

pub(super) fn lookup(scanner: Scanner, updates: &[(String, String)]) -> BTreeMap<String, Evidence> {
    if updates.is_empty() {
        return BTreeMap::new();
    }
    let deadline = Instant::now() + BUDGET;
    let index = (scanner == Scanner::AurSleuth)
        .then(sleuth::index)
        .flatten();
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
                        entries.push((
                            name.clone(),
                            one(
                                scanner,
                                name,
                                candidate,
                                deadline,
                                index.as_ref().and_then(|v| v.get(name)),
                            ),
                        ));
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
    fn watch_requires_an_explicit_matching_assessed_version() {
        let body = r#"{"pkg":"pkg","status":"medium","last_scanned":"2026-11-18","rules":[{"name":"Permission","severity":"medium","message":"Check setgid","matches":[{"file":".install","line":17,"text":"chmod g+s file"}]}]}"#;
        assert!(watch(body, "pkg", "2-1").is_none());
        let versioned = body.replace(r#""pkg":"pkg""#, r#""pkg":"pkg","scanned_version":"2-1""#);
        let e = watch(&versioned, "pkg", "2-1").unwrap();
        assert_eq!(e.category, Category::Suspicious);
        assert_eq!(e.version.as_deref(), Some("2-1"));
        assert_eq!(e.findings[1], ".install:17: chmod g+s file");
        assert!(watch(&versioned, "otherpkg", "2-1").is_none());
        assert!(watch(&versioned.replace("medium", "clean"), "pkg", "2-1").is_none());
        assert!(plain("\u{1b}[1m unsafe").is_none());
    }
}
