//! The dashboard index contains the service's adjudicated state, including confirmed malware.
//! Its aggregate spans recipe versions. Only per-audit records identify the version a model saw.

use super::*;
use std::sync::{Arc, Mutex};

struct Snapshot {
    etag: String,
    packages: Arc<Value>,
}
static INDEX: Mutex<Option<Snapshot>> = Mutex::new(None);

pub(super) fn index() -> Option<Arc<Value>> {
    let mut cache = INDEX.lock().ok()?;
    let mut args = vec![Scanner::AurSleuth.id()];
    if let Some(s) = cache.as_ref().filter(|s| !s.etag.is_empty()) {
        args.push(&s.etag);
    }
    let response = fetch(&args)?;
    let (body, status) = response.rsplit_once('\n')?;
    let (json, etag) = body.rsplit_once('\n')?;
    if status.trim() == "304" {
        return cache.as_ref().map(|s| Arc::clone(&s.packages));
    }
    if status.trim() != "200" {
        return None;
    }
    let mut data: Value = serde_json::from_str(json).ok()?;
    if !data["packages"].is_object() {
        return None;
    }
    let packages = Arc::new(data["packages"].take());
    // GitHub Pages supplies an ETag. Always revalidate before reusing a snapshot.
    let opaque = etag
        .strip_prefix("W/")
        .unwrap_or(etag)
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'));
    let usable = etag.len() <= 128
        && opaque.is_some_and(|tag| {
            !tag.is_empty()
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        });
    *cache = Some(Snapshot {
        etag: if usable { etag.into() } else { String::new() },
        packages: Arc::clone(&packages),
    });
    Some(packages)
}

/// Reports omit the epoch. Never strip an epoch from the candidate to make it match.
fn version(record: &Value) -> Option<String> {
    let ver = field(record, "pkgver")?;
    let rel = field(record, "pkgrel")?;
    if ver.contains(':') || rel.contains(':') {
        return None;
    }
    match record.get("epoch") {
        None => Some(format!("{ver}-{rel}")),
        Some(epoch) => {
            let epoch = epoch.as_str()?.parse::<u32>().ok()?;
            Some(if epoch == 0 {
                format!("{ver}-{rel}")
            } else {
                format!("{epoch}:{ver}-{rel}")
            })
        }
    }
}

pub(super) fn report(
    name: &str,
    candidate: &str,
    doc: &str,
    summary: Option<&Value>,
) -> Option<Evidence> {
    use std::collections::BTreeSet;
    if candidate.is_empty() {
        return None;
    }
    let details: Value = serde_json::from_str(doc).ok()?;
    let mut findings = Vec::new();
    let mut exact = BTreeSet::new();
    let mut unsafe_models = BTreeSet::new();
    let mut safe = false;
    let mut undecided = false;
    let mut one_version = true;
    for audit in details["audits"].as_array()? {
        let fm = &audit["frontmatter"];
        if fm["source"] == "community" || fm["advisory"] == "true" {
            continue;
        }
        if fm["package"] != name || version(fm).as_deref() != Some(candidate) {
            one_version = false;
            continue;
        }
        if !fm["files_reviewed"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
        {
            undecided = true;
            continue;
        }
        let model = field(fm, "model")?;
        let result = field(fm, "result")?;
        match result.as_str() {
            "safe" => safe = true,
            "unsafe" => {
                unsafe_models.insert(model.clone());
            }
            _ => undecided = true,
        }
        exact.insert(audit["filename"].as_str()?);
        findings.push(format!("Audit · {model}: {result}"));
    }
    if exact.is_empty() {
        return None;
    }
    let mut judge_unsafe = false;
    let mut judge_safe = false;
    for judge in details["judges"].as_array()? {
        let data = &judge["data"];
        // A judge names the audits it ruled on. A ruling across versions cannot
        // settle the candidate even when the latest package summary names its version.
        if data["package"] != name
            || !data["audits_judged"].as_array().is_some_and(|ids| {
                !ids.is_empty()
                    && ids
                        .iter()
                        .all(|id| id.as_str().is_some_and(|i| exact.contains(i)))
            })
        {
            one_version = false;
            continue;
        }
        let verdict = field(data, "correct_verdict")?;
        let model = field(&data["_judge_usage"], "model")?;
        match verdict.as_str() {
            "unsafe" => judge_unsafe = true,
            "safe" => judge_safe = true,
            _ => undecided = true,
        }
        findings.push(format!("Judge · {model}: {verdict}"));
    }
    let state = summary
        .filter(|p| one_version && version(p).as_deref() == Some(candidate))
        .and_then(|p| p["state"].as_str());
    let (category, label) = match state {
        Some("confirmed") if unsafe_models.len() >= 2 && judge_unsafe => {
            (Category::Malicious, "confirmed")
        }
        Some("clean") if judge_safe && !judge_unsafe => (Category::Clean, "clean"),
        // An adverse overview attributable to this release cannot support a clean
        // result when the detailed records fail to corroborate it.
        Some("confirmed" | "disputed" | "look") if !judge_unsafe && unsafe_models.is_empty() => {
            return None;
        }
        _ if judge_unsafe || !unsafe_models.is_empty() => {
            (Category::Suspicious, "Exact-version audits raised findings")
        }
        _ if safe && !undecided => (Category::Clean, "Exact-version audits reported safe"),
        _ => return None,
    };
    if findings.len() > 128 || findings.iter().map(String::len).sum::<usize>() > 65536 {
        if category != Category::Malicious {
            return None;
        }
        findings = vec!["Detailed audit records unavailable".into()];
    }
    Some(Evidence {
        details: Some(Vec::new()),
        scanner: Scanner::AurSleuth,
        version: Some(candidate.into()),
        category,
        summary: label.into(),
        findings,
        url: url(Scanner::AurSleuth, name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn audit(ver: &str, model: &str, verdict: &str) -> Value {
        json!({"filename":model,"frontmatter":{"package":"pkg","pkgver":ver,"pkgrel":"1","result":verdict,"files_reviewed":"3","model":model}})
    }
    #[test]
    fn package_summary_does_not_bind_old_audits_to_its_newest_version() {
        let data =
            json!({"audits":[audit("1","old","unsafe"),audit("2","new","safe")],"judges":[]});
        let aggregate = json!({"pkgver":"2","pkgrel":"1","state":"confirmed"});
        let e = report("pkg", "2-1", &data.to_string(), Some(&aggregate)).unwrap();
        assert_eq!(e.category, Category::Clean);
        assert_eq!(e.findings, ["Audit · new: safe"]);
        assert!(report("pkg", "3-1", &data.to_string(), Some(&aggregate)).is_none());
        assert!(report("pkg", "1:2-1", &data.to_string(), Some(&aggregate)).is_none());
    }
    #[test]
    fn conflicting_evidence_for_one_version_cannot_be_reported_clean() {
        let records = json!({"audits":[audit("2","only","safe")],"judges":[]});
        let aggregate = json!({"pkgver":"2","pkgrel":"1","state":"confirmed"});
        assert!(report("pkg", "2-1", &records.to_string(), Some(&aggregate)).is_none());
    }

    #[test]
    fn hard_block_requires_confirmed_state_and_version_bound_audits_and_judge() {
        let mut data = json!({"audits":[audit("2","first","unsafe"),audit("2","second","unsafe")],
            "judges":[{"data":{"package":"pkg","audits_judged":["first","second"],"correct_verdict":"unsafe","_judge_usage":{"model":"judge"}}}]});
        let aggregate = json!({"pkgver":"2","pkgrel":"1","state":"confirmed"});
        assert_eq!(
            report("pkg", "2-1", &data.to_string(), Some(&aggregate))
                .unwrap()
                .category,
            Category::Malicious
        );
        data["judges"][0]["data"]["audits_judged"] = json!(["first", "other-version"]);
        assert_eq!(
            report("pkg", "2-1", &data.to_string(), Some(&aggregate))
                .unwrap()
                .category,
            Category::Suspicious
        );
        assert_eq!(
            url(Scanner::AurSleuth, "foo++"),
            "https://mgalgs.io/aur-sleuth/#pkg=foo%2B%2B"
        );
    }
}
