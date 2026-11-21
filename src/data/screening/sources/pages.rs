//! Per-package pages keep lookups bounded. Verify package identity before reading scores.

use super::*;
use scraper::{ElementRef, Html, Selector};

fn select(css: &str) -> Selector {
    Selector::parse(css).expect("static CSS selector")
}

fn text(element: ElementRef<'_>) -> Option<String> {
    plain(&element.text().collect::<Vec<_>>().join(" "))
}

fn child_text(el: ElementRef<'_>, css: &str) -> Option<String> {
    text(el.select(&select(css)).next()?)
}

pub(super) fn lint(doc: &str, name: &str, candidate: &str) -> Option<Evidence> {
    let root = Html::parse_document(doc);
    let page = root.root_element();
    if child_text(page, ".pkghead h1")? != name
        || child_text(page, ".facts .repo")? != "aur"
        || child_text(page, ".facts b")? != candidate
    {
        return None;
    }
    let grade = child_text(page, ".stamp")?;
    let mut category = match grade.as_str() {
        "A" => Category::Clean,
        "B" | "C" => Category::Minor,
        "D" | "F" => Category::Suspicious,
        "?" => Category::Missing,
        _ => return None,
    };
    let mut findings = Vec::new();
    for row in page.select(&select(".finding")) {
        let sev = child_text(row, ".sev")?;
        let rank = match sev.as_str() {
            "info" | "warn" => Category::Minor,
            "error" | "critical" => Category::Suspicious,
            _ => return None,
        };
        category = category.max(rank);
        let rule = child_text(row, ".rid")?;
        let message = child_text(row, ".msg")?;
        let line = child_text(row, ".loc")?;
        let file = row
            .parent()?
            .prev_siblings()
            .find_map(ElementRef::wrap)
            .and_then(text)?;
        findings.push(format!("{rule} · {file} {line}: {message}"));
    }
    for row in page.select(&select(".note-alert li")) {
        findings.push(format!("Source drift: {}", text(row)?));
        category = category.max(Category::Suspicious);
    }
    if category == Category::Clean && !child_text(page, ".lede")?.starts_with("Nothing to report.")
    {
        return None;
    }
    Some(Evidence {
        details: Some(Vec::new()),
        scanner: Scanner::Pkglint,
        version: Some(candidate.to_owned()),
        category,
        summary: format!("PKGBUILD hygiene grade {grade}"),
        findings,
        url: url(Scanner::Pkglint, name),
    })
}

fn numeric_path<'a>(path: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let id = path.strip_prefix(prefix)?.strip_suffix(suffix)?;
    (!id.is_empty() && id.len() <= 16 && id.bytes().all(|b| b.is_ascii_digit())).then_some(id)
}

fn risk(label: &str) -> Option<Category> {
    let (value, meaning) = label.strip_prefix("Risk ")?.split_once("/5 · ")?;
    match (value, meaning) {
        ("0", "Safe") => Some(Category::Clean),
        ("1" | "2", _) => Some(Category::Minor),
        ("3" | "4" | "5", _) => Some(Category::Suspicious),
        _ => None,
    }
}

fn risks(row: ElementRef<'_>) -> Option<(Category, Vec<String>)> {
    let mut labels = Vec::new();
    let mut worst = Category::Clean;
    for mark in row.select(&select("span[title]")) {
        let label = plain(mark.value().attr("title")?)?;
        worst = worst.max(risk(&label)?);
        labels.push(label);
    }
    (!labels.is_empty()).then_some((worst, labels))
}

/// The search page resolves a package ID. Its overview badges can span versions;
/// only a Reviewed row in the version history identifies the candidate's scores.
fn ai_package(doc: &str, name: &str) -> Option<String> {
    let root = Html::parse_document(doc);
    root.select(&select("tbody a[href^='/packages/']"))
        .find_map(|link| {
            if text(link).as_deref() != Some(name) {
                return None;
            }
            numeric_path(link.value().attr("href")?, "/packages/", "/versions").map(str::to_owned)
        })
}

fn ai_version(doc: &str, name: &str, candidate: &str) -> Option<(Evidence, String)> {
    let root = Html::parse_document(doc);
    if child_text(root.root_element(), "h1 span")? != name {
        return None;
    }
    for row in root.select(&select("tbody tr")) {
        if row.select(&select("td")).nth(3).and_then(text).as_deref() != Some("Reviewed") {
            continue;
        }
        let Some(link) = row.select(&select("a[href^='/versions/']")).next() else {
            continue;
        };
        if text(link).as_deref() != Some(candidate) {
            continue;
        }
        let id = numeric_path(link.value().attr("href")?, "/versions/", "")?;
        let (category, findings) = risks(row)?;
        return Some((
            Evidence {
                details: (category == Category::Clean).then(Vec::new),
                scanner: Scanner::AurReview,
                version: Some(candidate.into()),
                category,
                summary: format!("{} hunk assessments", findings.len()),
                findings,
                url: format!("https://aur-review.com/versions/{id}"),
            },
            id.into(),
        ));
    }
    None
}

fn ai_comments(doc: &str, name: &str, id: &str, scores: &[String]) -> Option<Vec<String>> {
    let root = Html::parse_document(doc);
    let heading = root.select(&select("main h1 + p")).next()?;
    let span = select("span");
    let mut spans = heading.select(&span);
    if text(spans.next()?)? != format!("#{id}") || text(spans.next()?)? != name {
        return None;
    }
    let mut findings = Vec::new();
    let header = select("header span");
    for article in root.select(&select("article")) {
        let mut fields = article.select(&header);
        let score = text(fields.next()?)?;
        if scores.get(findings.len()) != Some(&score) {
            return None;
        }
        let file = text(fields.next()?)?;
        let comment = child_text(article, "p.whitespace-pre-wrap")?;
        findings.push(format!("{file} · {score}: {comment}"));
    }
    (findings.len() == scores.len()).then_some(findings)
}

fn summarize_scores(mut evidence: Evidence) -> Evidence {
    let mut counts = BTreeMap::new();
    for score in &evidence.findings {
        *counts.entry(score.as_str()).or_insert(0) += 1;
    }
    evidence.findings = counts
        .into_iter()
        .map(|(score, count)| format!("{score} × {count}"))
        .collect();
    evidence
}

pub(super) fn ai(doc: &str, name: &str, candidate: &str, deadline: Instant) -> Option<Evidence> {
    ai_with(doc, name, candidate, |path| {
        if Instant::now() >= deadline {
            return None;
        }
        fetch(&["aur-review", name, path])
    })
}

fn ai_with(
    doc: &str,
    name: &str,
    candidate: &str,
    mut page: impl FnMut(&str) -> Option<String>,
) -> Option<Evidence> {
    let pkgid = ai_package(doc, name)?;
    let history = page(&format!("packages/{pkgid}"))?;
    let (mut e, version_id) = ai_version(&history, name, candidate)?;
    if e.category != Category::Clean {
        e.details = page(&format!("versions/{version_id}"))
            .and_then(|doc| ai_comments(&doc, name, &version_id, &e.findings));
    }
    Some(summarize_scores(e))
}

fn cretezy_summary(doc: &str, name: &str, candidate: &str) -> Option<(Evidence, String)> {
    let root = Html::parse_document(doc);
    let prefix = format!("/checks/{name}/");
    for row in root.select(&select("article")) {
        let Some(link) = row.select(&select("a[href^='/checks/']")).next() else {
            continue;
        };
        let Some(commit) = link.value().attr("href")?.strip_prefix(&prefix) else {
            continue;
        };
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let title = text(link)?;
        let version = title.strip_prefix(name)?.strip_prefix(' ')?;
        if version != candidate {
            continue;
        }
        let Some(verdict) = child_text(row, "strong.capitalize") else {
            continue;
        };
        let category = match verdict.as_str() {
            "safe" => Category::Clean,
            "suspicious" | "dangerous" => Category::Suspicious,
            _ => continue,
        };
        return Some((
            Evidence {
                details: (category == Category::Clean).then(Vec::new),
                scanner: Scanner::Cretezy,
                version: Some(version.into()),
                category,
                summary: verdict,
                findings: vec![format!("Recipe commit {commit}")],
                url: format!("https://aur-security.cretezy.com{prefix}{commit}"),
            },
            commit.to_owned(),
        ));
    }
    None
}

fn assessment(doc: &str, name: &str, commit: &str, e: &Evidence) -> Option<Vec<String>> {
    let json: Value = serde_json::from_str(doc).ok()?;
    let row = json["results"].as_array()?.first()?;
    let record = row["commits"].as_array()?.first()?;
    let a = &record["assessment"];
    if row["package_base"].as_str()? != name
        || record["commit"].as_str()? != commit
        || a["verdict"].as_str()? != e.summary
        || a["version"].as_str() != e.version.as_deref()
    {
        return None;
    }
    Some(vec![
        format!("{} · {}", field(a, "provider")?, field(a, "model")?),
        field(a, "explanation")?,
    ])
}

pub(super) fn cretezy(
    doc: &str,
    name: &str,
    candidate: &str,
    deadline: Instant,
) -> Option<Evidence> {
    cretezy_with(doc, name, candidate, |commit| {
        if Instant::now() >= deadline {
            return None;
        }
        fetch(&["cretezy", name, commit])
    })
}

fn cretezy_with(
    doc: &str,
    name: &str,
    candidate: &str,
    lookup: impl FnOnce(&str) -> Option<String>,
) -> Option<Evidence> {
    let (mut e, commit) = cretezy_summary(doc, name, candidate)?;
    if e.category != Category::Clean {
        e.details = lookup(&commit).and_then(|doc| assessment(&doc, name, &commit, &e));
    }
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hygiene_grade_is_versioned_and_source_drift_requires_inspection() {
        let doc = r#"<div class=pkghead><h1>pkg</h1><div class='stamp stamp-A'>A</div><div class=facts><span class=repo>aur</span><b>1:2-1</b></div></div><p class=lede>Nothing to report. Sources are pinned.</p>"#;
        assert!(lint(doc, "pkg", "2-1").is_none());
        let clean = lint(doc, "pkg", "1:2-1").unwrap();
        assert_eq!(clean.version.as_deref(), Some("1:2-1"));
        assert_eq!(clean.category, Category::Clean);
        assert!(lint(doc, "other", "1:2-1").is_none());
        assert!(lint(&doc.replace(">aur<", ">extra<"), "pkg", "1:2-1").is_none());
        let drift = lint(
            &format!("{doc}<div class=note-alert><ul><li>A moved pin</li></ul></div>"),
            "pkg",
            "1:2-1",
        )
        .unwrap();
        assert_eq!(drift.category, Category::Suspicious);
    }
    #[test]
    fn ai_discovers_the_exact_package_and_requires_its_version_record() {
        let doc = r#"<table><tbody><tr><td>1</td><td><a href='/packages/1/versions'>pkg</a></td><td>1-2</td><td><span title='Risk 1/5 · Low'></span><span title='Risk 4/5 · High'></span></td></tr></tbody></table>"#;
        assert_eq!(ai_package(doc, "pkg").as_deref(), Some("1"));
        assert!(ai_package(doc, "p").is_none());
        assert!(ai_with(doc, "pkg", "1-2", |_| None).is_none());
        assert_eq!(risk("Risk 5/5 · Malicious"), Some(Category::Suspicious));
    }
    #[test]
    fn ai_archive_selects_the_exact_review_even_without_a_usable_latest_summary() {
        let page = r#"<table><tbody><tr><td>1</td><td><a href='/packages/9/versions'>pkg</a></td><td></td></tr></tbody></table>"#;
        assert_eq!(ai_package(page, "pkg").as_deref(), Some("9"));
        let history = r#"<h1><span>pkg</span></h1><table><tbody>
        <tr><td><a href='/versions/4'>2-1</a></td><td/><td/><td>Reviewed</td><td><span title='Risk 4/5 · High'></span></td></tr>
        <tr><td><a href='/versions/3'>1:2-1</a></td><td></td><td></td><td>Reviewed</td><td><span title='Risk 0/5 · Safe'></span></td></tr>
        </tbody></table>"#;
        let (e, id) = ai_version(history, "pkg", "1:2-1").unwrap();
        assert_eq!(id, "3");
        assert_eq!(e.category, Category::Clean);
        assert!(ai_version(history, "pkg", "1:2-2").is_none());
        let exact = ai_with(page, "pkg", "1:2-1", |path| {
            assert_eq!(path, "packages/9");
            Some(history.into())
        })
        .unwrap();
        assert_eq!(exact.details, Some(Vec::new()));
        assert_eq!(exact.url, "https://aur-review.com/versions/3");
    }

    #[test]
    fn ai_enrichment_preserves_scores_and_identifies_text_changes() {
        let search = r#"<table><tbody><tr><td>1</td><td><a href='/packages/1/versions'>pkg</a></td><td>2-1</td><td><span title='Risk 1/5 · Low'></span></td></tr></tbody></table>"#;
        let versions = r#"<h1><span>pkg</span></h1><table><tbody><tr><td><a href='/versions/15'>2-1</a></td><td></td><td></td><td>Reviewed</td><td><span title='Risk 1/5 · Low'></span></td></tr></tbody></table>"#;
        let details = r#"<main><h1>Version</h1><p><span>#15</span><span>pkg</span></p></main><article><header><span>Risk 1/5 · Low</span><span>PKGBUILD</span></header><p class='whitespace-pre-wrap'>Unpinned source</p></article>"#;
        assert!(ai_with(search, "pkg", "2-1", |_| None).is_none());
        let history_only = ai_with(search, "pkg", "2-1", |path| {
            (path == "packages/1").then(|| versions.into())
        })
        .unwrap();
        let full = |details: &str| {
            ai_with(search, "pkg", "2-1", |path| match path {
                "packages/1" => Some(versions.into()),
                "versions/15" => Some(details.into()),
                _ => panic!("unexpected request {path}"),
            })
            .unwrap()
        };
        let inspected = full(details);
        assert_eq!(history_only.category, Category::Minor);
        assert_eq!(history_only.summary, inspected.summary);
        assert_eq!(history_only.findings, inspected.findings);
        assert!(history_only.details.is_none());
        assert_eq!(history_only.url, inspected.url);
        assert_eq!(
            inspected.details.unwrap(),
            ["PKGBUILD · Risk 1/5 · Low: Unpinned source"]
        );
        assert_ne!(
            full(details),
            full(&details.replace("Unpinned source", "Downloads during build"))
        );
        let changed = versions.replace("Risk 1/5 · Low", "Risk 2/5 · Medium");
        assert_ne!(
            ai_with(search, "pkg", "2-1", |p| (p == "packages/1")
                .then(|| changed.clone()))
            .unwrap()
            .findings,
            history_only.findings
        );
    }

    #[test]
    fn cretezy_enrichment_preserves_commit_and_verdict_and_identifies_text_changes() {
        let sha = "0123456789012345678901234567890123456789";
        let page = format!(
            "<article><strong><a href='/checks/pkg/{sha}'>pkg 2-1</a></strong><strong class=capitalize>suspicious</strong></article>"
        );
        let summary = cretezy_with(&page, "pkg", "2-1", |_| None).unwrap();
        let clean_page = page.replace(">suspicious<", ">safe<");
        let clean = cretezy_with(&clean_page, "pkg", "2-1", |_| {
            panic!("clean record needs no additional lookup")
        })
        .unwrap();
        assert_eq!(clean.category, Category::Clean);
        assert_eq!(clean.details, Some(Vec::new()));
        let rich = |explanation: &str| {
            cretezy_with(&page,"pkg","2-1", |commit| {
            assert_eq!(commit,sha);
            Some(serde_json::json!({"results":[{"package_base":"pkg","commits":[{"commit":sha,"assessment":{"verdict":"suspicious","version":"2-1","provider":"checker","model":"m","explanation":explanation}}]}]}).to_string())
        }).unwrap()
        };
        let full = rich("Downloads while building");
        assert_eq!(summary.category, Category::Suspicious);
        assert_eq!(summary.summary, full.summary);
        assert_eq!(summary.findings, full.findings);
        assert_eq!(summary.url, full.url);
        assert!(summary.details.is_none());
        assert_eq!(
            full.details.as_deref().unwrap(),
            ["checker · m", "Downloads while building"]
        );
        assert_ne!(full, rich("An unpinned source"));
    }

    #[test]
    fn commit_lookup_verifies_name_version_and_commit() {
        let sha = "0123456789012345678901234567890123456789";
        let doc = format!(
            "<article><strong><a href='/checks/pkg/{sha}'>pkg 1-1</a></strong><strong class=capitalize>suspicious</strong></article>"
        );
        assert!(cretezy_summary(&doc, "pkg", "1-2").is_none());
        let (e, c) = cretezy_summary(&doc, "pkg", "1-1").unwrap();
        assert_eq!(c, sha);
        let response = serde_json::json!({"results":[{"package_base":"pkg","commits":[{"commit":sha,"assessment":{"verdict":"suspicious","version":"1-1","provider":"test","model":"AI","explanation":"Check network access"}}]}]}).to_string();
        assert!(assessment(&response, "pkg", sha, &e).is_some());
        assert!(assessment(&response, "other", sha, &e).is_none());
    }
}
