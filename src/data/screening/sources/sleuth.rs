//! The dashboard index contains the service's adjudicated state, including confirmed malware.
//! Individual audit files contain unadjudicated model opinions and can exceed the index in size.

use super::*;
use std::sync::{Arc, Mutex};

struct Snapshot {
    etag: String,
    packages: Arc<Value>,
}
static INDEX: Mutex<Option<Snapshot>> = Mutex::new(None);

fn index() -> Option<Arc<Value>> {
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

fn report(name: &str, package: &Value) -> Option<Evidence> {
    let state = package["state"].as_str()?;
    let category = match state {
        "clean" => Category::Clean,
        "disputed" | "look" => Category::Suspicious,
        "confirmed" => Category::Malicious,
        "unknown" => Category::Missing,
        _ => return None,
    };
    let version = field(package, "pkgver")
        .zip(field(package, "pkgrel"))
        .map(|(v, r)| format!("{v}-{r}"));
    let mut findings = Vec::new();
    // Audits and judges are presented separately so a false positive overturned by a judge
    // retains its context. The published state, not our own tally, determines the category.
    let audits = package["audits"].as_array();
    let judges = package["judges"].as_array();
    let details = || -> Option<Vec<String>> {
        let mut items = vec![];
        for (records, label, key) in [(audits?, "Audit", "result"), (judges?, "Judge", "verdict")] {
            if records.len() > 64 {
                return None;
            }
            for r in records {
                items.push(format!(
                    "{label} · {}: {}",
                    field(r, "model")?,
                    field(r, key)?
                ));
            }
        }
        (items.iter().map(String::len).sum::<usize>() <= 65536).then_some(items)
    };
    if let Some(items) = details() {
        if items.is_empty() && category == Category::Clean {
            return None;
        }
        findings.extend(items);
    } else if category == Category::Clean {
        return None;
    } else {
        findings.push("Detailed audit records unavailable".into());
    }
    let stamp = field(package, "latest_date").unwrap_or_default();
    Some(Evidence {
        scanner: Scanner::AurSleuth,
        version,
        category,
        summary: format!("{state} · {stamp}"),
        findings,
        url: url(Scanner::AurSleuth, name),
    })
}

pub(super) fn lookup(updates: &[(String, String)]) -> BTreeMap<String, Evidence> {
    let data = index();
    updates
        .iter()
        .map(|(name, _)| {
            let e = data
                .as_ref()
                .and_then(|d| report(name, &d[name]))
                .unwrap_or_else(|| {
                    missing(
                        Scanner::AurSleuth,
                        name,
                        if data.is_none() {
                            "Service unavailable"
                        } else {
                            "No readable assessment for this package"
                        },
                    )
                });
            (name.clone(), e)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_published_confirmed_state_is_malicious() {
        let mut data = json!({"state":"clean","pkgver":"2","pkgrel":"1","audits":[{"result":"unsafe","model":"a"}],"judges":[{"verdict":"safe","model":"b"}]});
        assert_eq!(report("paru", &data).unwrap().category, Category::Clean);
        data["state"] = json!("disputed");
        assert_eq!(
            report("paru", &data).unwrap().category,
            Category::Suspicious
        );
        data["state"] = json!("confirmed");
        data["audits"] = Value::Null;
        let e = report("paru", &data).unwrap();
        assert_eq!(e.category, Category::Malicious);
        assert_eq!(e.version.as_deref(), Some("2-1"));
        data["audits"] = Value::Array(vec![json!({"result":"unsafe","model":"a"}); 65]);
        let capped = report("paru", &data).unwrap();
        assert_eq!(capped.category, Category::Malicious);
        assert_eq!(capped.findings, ["Detailed audit records unavailable"]);
    }
}
