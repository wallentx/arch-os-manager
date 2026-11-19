//! Public scanner evidence and authorization for a selected AUR update.

mod sources;
mod wtako;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::updates::{Source, Update};
use crate::i18n::t;
use crate::settings::Settings;
use crate::state::State;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scanner {
    Wtako,
    Aurwatch,
    Pkglint,
    AurReview,
    AurSleuth,
    Cretezy,
}

impl Scanner {
    pub const ALL: [Self; 6] = [
        Self::Wtako,
        Self::Aurwatch,
        Self::Pkglint,
        Self::AurReview,
        Self::AurSleuth,
        Self::Cretezy,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::Wtako => "wtako",
            Self::Aurwatch => "aurwatch",
            Self::Pkglint => "pkglint",
            Self::AurReview => "aur-review",
            Self::AurSleuth => "aur-sleuth",
            Self::Cretezy => "cretezy",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Wtako => "WTAKO AUR Audit",
            Self::Aurwatch => "AURWatch",
            Self::Pkglint => "pkglint",
            Self::AurReview => "AUR AI Reviewer",
            Self::AurSleuth => "AUR Sleuth",
            Self::Cretezy => "Cretezy AUR Security",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Clean,
    Minor,
    Suspicious,
    #[default]
    Missing,
    Malicious,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => t("No findings"),
            Self::Minor => t("Minor findings"),
            Self::Suspicious => t("Suspicious findings"),
            Self::Missing => t("Missing scan"),
            Self::Malicious => t("Confirmed malicious"),
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Minor => "minor",
            Self::Suspicious => "suspicious",
            Self::Missing => "missing",
            Self::Malicious => "malicious",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    Allow,
    Inspect,
    Defer,
    Block,
}

impl Policy {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => t("Allow"),
            Self::Inspect => t("Inspect"),
            Self::Defer => t("Defer"),
            Self::Block => t("Block"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub scanner: Scanner,
    /// The version identified by the provider, if any.
    pub version: Option<String>,
    pub category: Category,
    pub summary: String,
    pub findings: Vec<String>,
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    // Older state files stored one WTAKO report. Its empty evidence cannot authorize an update.
    #[serde(default)]
    pub category: Category,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

impl Report {
    pub fn new(version: &str, evidence: Vec<Evidence>) -> Self {
        let mut report = Self {
            version: version.into(),
            category: Category::Missing,
            evidence,
        };
        report.category = report.classify();
        report
    }

    fn classify(&self) -> Category {
        let mut category = Category::Missing;
        for item in &self.evidence {
            if item.category == Category::Malicious {
                return Category::Malicious;
            }
            let exact = item.version.as_deref() == Some(&self.version) && !self.version.is_empty();
            if item.version.is_some() && !exact {
                continue;
            }
            match item.category {
                Category::Suspicious => category = Category::Suspicious,
                Category::Minor if category != Category::Suspicious => category = Category::Minor,
                Category::Clean if exact && category == Category::Missing => {
                    category = Category::Clean
                }
                _ => {}
            }
        }
        category
    }
}

fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
        && !name.starts_with(['-', '.'])
}

/// An exception covers exactly the displayed evidence from the currently enabled sources.
fn active_report(name: &str, report: &Report, settings: &Settings, state: &State) -> bool {
    let mut enabled = Scanner::ALL
        .into_iter()
        .filter(|s| settings.scanner_enabled(*s))
        .peekable();
    settings.aur_screening
        && enabled.peek().is_some()
        && enabled.eq(report.evidence.iter().map(|e| e.scanner))
        && !report.version.is_empty()
        && report.classify() == report.category
        && report.category != Category::Malicious
        && !state.aur_holds.contains_key(name)
        && !state.aur_malicious.contains_key(name)
        && !state.deferred(name, settings)
}

pub fn inspectable(name: &str, report: &Report, settings: &Settings, state: &State) -> bool {
    active_report(name, report, settings, state)
        && settings.screening_policy(report.category) == Policy::Inspect
}

pub fn eligible(name: &str, report: &Report, settings: &Settings, state: &State) -> bool {
    if !active_report(name, report, settings, state) {
        return false;
    }
    match settings.screening_policy(report.category) {
        Policy::Allow => report.category == Category::Clean,
        Policy::Inspect => state.aur_trust.get(name) == Some(report),
        Policy::Defer | Policy::Block => false,
    }
}

fn by_base(scanner: Scanner) -> bool {
    matches!(
        scanner,
        Scanner::Wtako | Scanner::AurReview | Scanner::Cretezy
    )
}

/// These services index recipes by the AUR package base, which split packages share.
fn base_names(
    candidates: &[(String, String)],
    packages: &[super::aur::Package],
) -> BTreeMap<String, String> {
    let versions: BTreeMap<_, _> = candidates.iter().map(|(n, v)| (n, v)).collect();
    packages
        .iter()
        .filter(|p| {
            p.name != p.package_base
                && package_name(&p.package_base)
                && versions.get(&p.name) == Some(&&p.version)
        })
        .map(|p| (p.name.clone(), p.package_base.clone()))
        .collect()
}

fn assess(
    candidates: &[(String, String)],
    settings: &Settings,
    packages: &[super::aur::Package],
) -> BTreeMap<String, Report> {
    if candidates.is_empty() || !settings.aur_screening {
        return BTreeMap::new();
    }
    let bases = base_names(candidates, packages);
    let mut recipes = candidates
        .iter()
        .map(|(n, v)| (bases.get(n).unwrap_or(n).clone(), v.clone()))
        .collect::<Vec<_>>();
    recipes.sort();
    recipes.dedup();
    // Each service is independent. Preserve provider order even when requests finish out of order.
    let answers = std::thread::scope(|scope| {
        let jobs: Vec<_> = Scanner::ALL
            .into_iter()
            .filter(|s| settings.scanner_enabled(*s))
            .map(|s| {
                let targets = if by_base(s) {
                    recipes.as_slice()
                } else {
                    candidates
                };
                (
                    s,
                    scope.spawn(move || match s {
                        Scanner::Wtako => wtako::lookup(targets),
                        _ => sources::lookup(s, targets),
                    }),
                )
            })
            .collect();
        jobs.into_iter()
            .map(|(s, job)| (s, job.join().unwrap_or_default()))
            .collect::<Vec<_>>()
    });
    candidates
        .iter()
        .map(|(name, version)| {
            let evidence = answers
                .iter()
                .map(|(scanner, results)| {
                    let key = if by_base(*scanner) {
                        bases.get(name).unwrap_or(name)
                    } else {
                        name
                    };
                    let mut record = results.get(key).cloned().unwrap_or_else(|| Evidence {
                        scanner: *scanner,
                        version: None,
                        category: Category::Missing,
                        summary: "No report available".into(),
                        findings: Vec::new(),
                        url: String::new(),
                    });
                    if key != name {
                        record.summary = format!("{} (package base {key})", record.summary);
                    }
                    record
                })
                .collect();
            (name.clone(), Report::new(version, evidence))
        })
        .collect()
}

pub fn lookup(updates: &[Update], settings: &Settings) -> BTreeMap<String, Report> {
    let candidates = updates
        .iter()
        .filter(|u| u.source == Source::Aur && package_name(&u.name))
        .map(|u| (u.name.clone(), u.new.clone()))
        .collect::<Vec<_>>();
    let mut packages = Vec::new();
    if settings.aur_screening
        && Scanner::ALL
            .into_iter()
            .any(|s| by_base(s) && settings.scanner_enabled(s))
    {
        // Base discovery is optional. Fall back to the installed name if the AUR is slow or offline.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for batch in candidates.chunks(24) {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            if let Ok(mut rows) = package_info(batch, left) {
                packages.append(&mut rows);
            }
        }
    }
    assess(&candidates, settings, &packages)
}

fn package_info(
    batch: &[(String, String)],
    limit: std::time::Duration,
) -> Result<Vec<super::aur::Package>, crate::script::Failure> {
    let names = batch.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>();
    let out = crate::script::query_within(crate::script::op::PACKAGES_AUR_INFO, &names, limit)?;
    if out.len() > 4 * 1024 * 1024 {
        return Err(rejected());
    }
    super::aur::parse(&out).map_err(|_| rejected())
}

fn rejected() -> crate::script::Failure {
    crate::script::Failure::classify(crate::script::op::UPGRADE_RUN, Some(14), None, Vec::new())
}

/// Ordinary clean results can lose a corroborating provider and still meet the
/// clean policy. An inspection decision is tied to the individual findings.
fn still_approved(expected: &Report, fresh: &Report) -> bool {
    expected == fresh
        || (expected.category == Category::Clean
            && fresh.category == Category::Clean
            && expected.version == fresh.version
            && expected
                .evidence
                .iter()
                .map(|e| e.scanner)
                .eq(fresh.evidence.iter().map(|e| e.scanner)))
}

fn arguments(
    expected: &BTreeMap<String, Report>,
    fresh: &BTreeMap<String, Report>,
    settings: &Settings,
    state: &State,
    packages: &[super::aur::Package],
) -> Result<Vec<String>, crate::script::Failure> {
    if expected.is_empty() || expected.len() != fresh.len() {
        return Err(rejected());
    }
    let mut args = vec!["screened".into()];
    for (name, report) in expected {
        let current = fresh
            .get(name)
            .filter(|new| still_approved(report, new))
            .ok_or_else(rejected)?;
        let mut found = packages.iter().filter(|p| &p.name == name);
        let package = found.next().ok_or_else(rejected)?;
        if found.next().is_some()
            || !package_name(name)
            || !package_name(&package.package_base)
            || state.aur_malicious.contains_key(&package.package_base)
            || package.version != report.version
            || report.version.len() > 200
            || report
                .version
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || !eligible(name, current, settings, state)
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

pub fn verify(expected: &BTreeMap<String, Report>) -> Result<Vec<String>, crate::script::Failure> {
    let settings = || match Settings::load() {
        (s, None) if s.aur_screening => Ok(s),
        _ => Err(rejected()),
    };
    let selected: Vec<_> = expected
        .iter()
        .map(|(n, r)| (n.clone(), r.version.clone()))
        .collect();
    if selected.is_empty() || selected.iter().any(|(n, _)| !package_name(n)) {
        return Err(rejected());
    }
    let initial = settings()?;
    let generation = State::try_load()
        .map_err(|_| rejected())?
        .aur_block_generation;
    let mut packages = Vec::new();
    for batch in selected.chunks(24) {
        packages.extend(package_info(batch, std::time::Duration::from_secs(10))?);
    }
    let fresh = assess(&selected, &initial, &packages);
    let latest = settings();
    let state = State::try_update(|s| {
        s.observe_malicious(&fresh, Some(generation));
        if let Ok(safety_settings) = &latest {
            s.apply_policies(&fresh, safety_settings);
        }
        s.aur_trust.retain(|name, approved| {
            expected.get(name) != Some(approved) || fresh.get(name) == Some(approved)
        });
    })
    .map_err(|_| rejected())?;
    if selected.iter().any(|(n, _)| {
        !fresh
            .get(n)
            .is_some_and(|r| still_approved(&expected[n], r) && eligible(n, r, &initial, &state))
    }) {
        return Err(rejected());
    }
    arguments(
        expected,
        &fresh,
        &settings()?,
        &State::try_load().map_err(|_| rejected())?,
        &packages,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(scanner: Scanner, category: Category, version: Option<&str>) -> Evidence {
        Evidence {
            scanner,
            category,
            version: version.map(str::to_string),
            summary: scanner.label().into(),
            findings: vec![],
            url: String::new(),
        }
    }

    fn settings(sources: &[Scanner]) -> Settings {
        let mut s = Settings {
            aur_screening: true,
            ..Settings::default()
        };
        for scanner in Scanner::ALL {
            s.set_scanner_enabled(scanner, sources.contains(&scanner));
        }
        s
    }

    #[test]
    fn aggregation_preserves_old_reports_and_weighs_current_observations() {
        use Category::*;
        let mut evidence = vec![
            observed(Scanner::Wtako, Suspicious, Some("old")),
            observed(Scanner::Aurwatch, Clean, None),
            observed(Scanner::Pkglint, Missing, None),
        ];
        let historical = Report::new("new", evidence.clone());
        assert_eq!(historical.category, Missing);
        assert_eq!(historical.evidence, evidence);
        evidence.push(observed(Scanner::Cretezy, Clean, Some("new")));
        assert_eq!(Report::new("new", evidence.clone()).category, Clean);
        evidence[1].category = Minor;
        assert_eq!(Report::new("new", evidence.clone()).category, Minor);
        evidence[1].category = Suspicious;
        assert_eq!(Report::new("new", evidence.clone()).category, Suspicious);
        evidence[0].category = Malicious;
        assert_eq!(Report::new("new", evidence).category, Malicious);
    }

    #[test]
    fn policies_source_selection_and_approvals_are_enforced_for_install() {
        let mut s = settings(&[Scanner::Wtako]);
        let mut state = State::default();
        let source = |cat| Report::new("2-1", vec![observed(Scanner::Wtako, cat, Some("2-1"))]);
        let mut r = source(Category::Minor);
        assert!(inspectable("pkg", &r, &s, &state));
        assert!(!eligible("pkg", &r, &s, &state));
        state.aur_trust.insert("pkg".into(), r.clone());
        assert!(eligible("pkg", &r, &s, &state));
        let pkgs = super::super::aur::parse(r#"{"type":"multiinfo","results":[{"Name":"pkg","PackageBase":"base","Version":"2-1"}]}"#).unwrap();
        let selected = BTreeMap::from([("pkg".into(), r.clone())]);
        assert_eq!(
            arguments(&selected, &selected, &s, &state, &pkgs).unwrap(),
            ["screened", "pkg", "2-1", "base"]
        );
        r.evidence[0].findings.push("new finding".into());
        assert!(!eligible("pkg", &r, &s, &state));
        for policy in [Policy::Defer, Policy::Block] {
            s.set_screening_policy(Category::Minor, policy);
            assert!(arguments(&selected, &selected, &s, &state, &pkgs).is_err());
        }
        s.set_screening_policy(Category::Minor, Policy::Inspect);
        s.set_scanner_enabled(Scanner::Wtako, false);
        assert!(!eligible("pkg", &selected["pkg"], &s, &state));
        assert!(!inspectable("pkg", &Report::new("2-1", vec![]), &s, &state));
        s.set_scanner_enabled(Scanner::Wtako, true);
        let bad = source(Category::Malicious);
        state.aur_trust.insert("pkg".into(), bad.clone());
        assert!(!inspectable("pkg", &bad, &s, &state));
        let selected = BTreeMap::from([("pkg".into(), bad)]);
        assert!(arguments(&selected, &selected, &s, &state, &pkgs).is_err());
    }

    #[test]
    fn split_package_lookups_require_a_matching_aur_version_and_base() {
        let packages = super::super::aur::parse(r#"{"type":"multiinfo","results":[{"Name":"libfoo","PackageBase":"foo","Version":"2-1"},{"Name":"gone","PackageBase":"other","Version":"old"}]}"#).unwrap();
        let selected = [
            ("libfoo".into(), "2-1".into()),
            ("gone".into(), "new".into()),
        ];
        assert_eq!(
            base_names(&selected, &packages),
            BTreeMap::from([("libfoo".into(), "foo".into())])
        );
    }

    #[test]
    fn one_service_outage_keeps_an_independent_current_clean_result() {
        let s = settings(&[Scanner::Wtako, Scanner::Cretezy]);
        let reports = |second| {
            BTreeMap::from([(
                "pkg".into(),
                Report::new(
                    "2-1",
                    vec![
                        observed(Scanner::Wtako, Category::Clean, Some("2-1")),
                        observed(Scanner::Cretezy, second, Some("2-1")),
                    ],
                ),
            )])
        };
        let pkgs = super::super::aur::parse(r#"{"type":"multiinfo","results":[{"Name":"pkg","PackageBase":"pkg","Version":"2-1"}]}"#).unwrap();
        let first = reports(Category::Clean);
        assert!(
            arguments(
                &first,
                &reports(Category::Missing),
                &s,
                &State::default(),
                &pkgs
            )
            .is_ok()
        );
        for category in [Category::Minor, Category::Suspicious, Category::Malicious] {
            assert!(arguments(&first, &reports(category), &s, &State::default(), &pkgs).is_err());
        }
    }
}
