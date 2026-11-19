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

pub(super) fn lint(doc: &str, name: &str) -> Option<Evidence> {
    let root = Html::parse_document(doc);
    let page = root.root_element();
    if child_text(page, ".pkghead h1")? != name || child_text(page, ".facts .repo")? != "aur" {
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
        scanner: Scanner::Pkglint,
        version: Some(child_text(page, ".facts b")?),
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

fn ai_summary(doc: &str, name: &str) -> Option<(Evidence, String)> {
    let root = Html::parse_document(doc);
    for row in root.select(&select("tbody tr")) {
        let Some(link) = row.select(&select("a[href^='/packages/']")).next() else {
            continue;
        };
        if text(link)?.as_str() != name {
            continue;
        }
        let id = numeric_path(link.value().attr("href")?, "/packages/", "/versions")?;
        let version = text(row.select(&select("td")).nth(2)?)?;
        let (category, findings) = risks(row)?;
        return Some((
            Evidence {
                scanner: Scanner::AurReview,
                version: Some(version),
                category,
                summary: format!("{} hunk assessments", findings.len()),
                findings,
                url: format!("https://aur-review.com/packages/{id}/versions"),
            },
            id.into(),
        ));
    }
    None
}

fn ai_version(doc: &str, name: &str, candidate: &str) -> Option<(Evidence, String)> {
    let root = Html::parse_document(doc);
    if child_text(root.root_element(), "h1 span")? != name {
        return None;
    }
    let mut latest = None;
    for row in root.select(&select("tbody tr")) {
        if text(row.select(&select("td")).nth(3)?)? != "Reviewed" {
            continue;
        }
        let link = row.select(&select("a[href^='/versions/']")).next()?;
        let version = text(link)?;
        let id = numeric_path(link.value().attr("href")?, "/versions/", "")?;
        if latest.is_some() && version != candidate {
            continue;
        }
        let (category, findings) = risks(row)?;
        let e = Evidence {
            scanner: Scanner::AurReview,
            version: Some(version.clone()),
            category,
            summary: format!("{} hunk assessments", findings.len()),
            findings,
            url: format!("https://aur-review.com/versions/{id}"),
        };
        latest = Some((e, id.to_string()));
        if version == candidate {
            break;
        }
    }
    latest
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
    if evidence.findings.iter().all(|s| risk(s).is_some()) {
        let mut counts = BTreeMap::new();
        for score in &evidence.findings {
            *counts.entry(score.as_str()).or_insert(0) += 1;
        }
        evidence.findings = counts
            .into_iter()
            .map(|(score, count)| format!("{score} × {count}"))
            .collect();
    }
    evidence
}

pub(super) fn ai(doc: &str, name: &str, candidate: &str, deadline: Instant) -> Option<Evidence> {
    let (summary, pkgid) = ai_summary(doc, name)?;
    if Instant::now() >= deadline {
        return Some(summarize_scores(summary));
    }
    let Some((mut e, version_id)) = fetch(&["aur-review", name, &format!("packages/{pkgid}")])
        .and_then(|page| ai_version(&page, name, candidate))
    else {
        return Some(summarize_scores(summary));
    };
    if e.category != Category::Clean
        && Instant::now() < deadline
        && let Some(comments) = fetch(&["aur-review", name, &format!("versions/{version_id}")])
            .and_then(|page| ai_comments(&page, name, &version_id, &e.findings))
    {
        e.findings = comments;
    }
    Some(summarize_scores(e))
}

fn cretezy_summary(doc: &str, name: &str, candidate: &str) -> Option<(Evidence, String)> {
    let root = Html::parse_document(doc);
    let mut latest = None;
    let prefix = format!("/checks/{name}/");
    for row in root.select(&select("article")) {
        let link = row.select(&select("a[href^='/checks/']")).next()?;
        let Some(commit) = link.value().attr("href")?.strip_prefix(&prefix) else {
            continue;
        };
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let title = text(link)?;
        let version = title.strip_prefix(name)?.strip_prefix(' ')?;
        if version.is_empty() || (latest.is_some() && version != candidate) {
            continue;
        }
        let verdict = child_text(row, "strong.capitalize")?;
        let category = match verdict.as_str() {
            "safe" => Category::Clean,
            "suspicious" | "dangerous" => Category::Suspicious,
            _ => Category::Missing,
        };
        latest = Some((
            Evidence {
                scanner: Scanner::Cretezy,
                version: Some(version.into()),
                category,
                summary: verdict,
                findings: vec![format!("Recipe commit {commit}")],
                url: format!("https://aur-security.cretezy.com{prefix}{commit}"),
            },
            commit.to_owned(),
        ));
        if version == candidate {
            break;
        }
    }
    latest
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
    let mut lines = vec![format!(
        "{} · {}",
        field(a, "provider")?,
        field(a, "model")?
    )];
    if let Some(value) = a["explanation"].as_str() {
        lines.push(plain(value)?);
    }
    Some(lines)
}

pub(super) fn cretezy(
    doc: &str,
    name: &str,
    candidate: &str,
    deadline: Instant,
) -> Option<Evidence> {
    let (mut e, commit) = cretezy_summary(doc, name, candidate)?;
    if Instant::now() < deadline
        && let Some(lines) =
            fetch(&["cretezy", name, &commit]).and_then(|doc| assessment(&doc, name, &commit, &e))
    {
        e.findings.extend(lines);
    }
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hygiene_grade_is_versioned_and_source_drift_requires_inspection() {
        let doc = r#"<div class=pkghead><h1>pkg</h1><div class='stamp stamp-A'>A</div><div class=facts><span class=repo>aur</span><b>1:2-1</b></div></div><p class=lede>Nothing to report. Sources are pinned.</p>"#;
        let clean = lint(doc, "pkg").unwrap();
        assert_eq!(clean.version.as_deref(), Some("1:2-1"));
        assert_eq!(clean.category, Category::Clean);
        assert!(lint(doc, "other").is_none());
        assert!(lint(&doc.replace(">aur<", ">extra<"), "pkg").is_none());
        let drift = lint(
            &format!("{doc}<div class=note-alert><ul><li>A moved pin</li></ul></div>"),
            "pkg",
        )
        .unwrap();
        assert_eq!(drift.category, Category::Suspicious);
    }
    #[test]
    fn ai_uses_the_exact_search_hit_and_scores_each_hunk() {
        let doc = r#"<table><tbody><tr><td>1</td><td><a href='/packages/1/versions'>pkg</a></td><td>1-2</td><td><span title='Risk 1/5 · Low'></span><span title='Risk 4/5 · High'></span></td></tr></tbody></table>"#;
        let (e, id) = ai_summary(doc, "pkg").unwrap();
        assert_eq!((id.as_str(), e.category), ("1", Category::Suspicious));
        assert!(ai_summary(doc, "p").is_none());
        assert_eq!(risk("Risk 5/5 · Malicious"), Some(Category::Suspicious));
        assert!(ai_summary(&doc.replace("Risk 4/5", "Unknown"), "pkg").is_none());
    }
    #[test]
    fn commit_lookup_verifies_name_version_and_commit() {
        let sha = "0123456789012345678901234567890123456789";
        let doc = format!(
            "<article><strong><a href='/checks/pkg/{sha}'>pkg 1-1</a></strong><strong class=capitalize>suspicious</strong></article>"
        );
        let (e, c) = cretezy_summary(&doc, "pkg", "1-1").unwrap();
        assert_eq!(c, sha);
        let response = serde_json::json!({"results":[{"package_base":"pkg","commits":[{"commit":sha,"assessment":{"verdict":"suspicious","version":"1-1","provider":"test","model":"AI","explanation":"Check network access"}}]}]}).to_string();
        assert!(assessment(&response, "pkg", sha, &e).is_some());
        assert!(assessment(&response, "other", sha, &e).is_none());
    }
}
