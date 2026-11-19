//! `~/.arch-os/state.yaml`: what the program remembers between runs.

use std::collections::BTreeMap;

use crate::data::screening::{Category, Evidence, Report, Scanner};
use crate::data::updates::{Pending, Source};
use serde::{Deserialize, Serialize};
use std::{io, path::Path};

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct State {
    /// An exception applies only while the candidate version and findings still match.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aur_trust: BTreeMap<String, Report>,
    /// Keyed by name=version so an assessment cannot block a different release.
    #[serde(
        default,
        deserialize_with = "versioned_blocks",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub aur_malicious: BTreeMap<String, BTreeMap<Scanner, Evidence>>,
    /// A clean lookup may clear an earlier block only if no newer block was recorded meanwhile.
    #[serde(default, skip_serializing_if = "zero")]
    pub aur_block_generation: u64,
    /// The policy that deferred a package until a current clean scan.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aur_deferrals: BTreeMap<String, Category>,
    /// Explicitly held updates, released when the scanner clears the pending version.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aur_holds: BTreeMap<String, String>,
    /// Links of the news already read. Absent until the news were first loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub news_read: Option<Vec<String>>,
    /// The updates the last notification was about, so the same ones are not announced twice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notified: Vec<String>,
    /// The notification still standing unanswered, as its server and id, which the next one
    /// closes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification: Option<String>,
}

type Blocks = BTreeMap<String, BTreeMap<Scanner, Evidence>>;

/// Older state files grouped blocks by name. Import only verdicts that identify their version.
fn versioned_blocks<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Blocks, D::Error> {
    let mut blocks = Blocks::new();
    for (key, records) in Blocks::deserialize(d)? {
        let (name, keyed_version) = match key.split_once('=') {
            Some((name, version)) => (name, Some(version)),
            None => (key.as_str(), None),
        };
        for (scanner, evidence) in records {
            if let Some(v) = evidence.version.as_deref()
                && !v.is_empty()
                && keyed_version.is_none_or(|expected| expected == v)
                && evidence.category == Category::Malicious
                && evidence.scanner == scanner
            {
                blocks
                    .entry(format!("{name}={v}"))
                    .or_default()
                    .insert(scanner, evidence);
            }
        }
    }
    Ok(blocks)
}

fn zero(n: &u64) -> bool {
    *n == 0
}

impl State {
    pub fn load() -> State {
        State::load_from(&crate::paths::state())
    }

    /// Changes the file as it is now, so what the interface and the timer each wrote stays.
    pub fn update(change: impl FnOnce(&mut State)) -> State {
        Self::try_update(change).unwrap_or_else(|e| {
            crate::warn!("state not saved: {e}");
            Self::load()
        })
    }

    pub fn try_load() -> io::Result<State> {
        Self::read(&crate::paths::state())
    }

    pub fn try_update(change: impl FnOnce(&mut State)) -> io::Result<State> {
        Self::update_at(&crate::paths::state(), change)
    }

    pub fn has_malicious(&self) -> bool {
        !self.aur_malicious.is_empty()
    }

    pub fn malicious_evidence(&self, name: &str, version: &str) -> impl Iterator<Item = &Evidence> {
        self.aur_malicious
            .get(&format!("{name}={version}"))
            .into_iter()
            .flat_map(|s| s.values())
    }

    pub fn is_malicious(&self, name: &str, version: &str) -> bool {
        self.malicious_evidence(name, version).next().is_some()
    }

    pub fn blocks_pending(&self, pending: &Pending) -> bool {
        pending
            .updates
            .iter()
            .any(|u| u.source == Source::Aur && self.is_malicious(&u.name, &u.new))
            || (self.has_malicious() && pending.failed.contains(&Source::Aur))
    }

    pub fn deferred(&self, name: &str, settings: &crate::settings::Settings) -> bool {
        self.aur_deferrals
            .get(name)
            .is_some_and(|c| settings.screening_policy(*c) == crate::data::screening::Policy::Defer)
    }

    /// Only a clean, version-matched assessment from the same provider releases its own block.
    pub(crate) fn observe_malicious(
        &mut self,
        reports: &BTreeMap<String, Report>,
        started_at: Option<u64>,
    ) {
        let can_clear = started_at == Some(self.aur_block_generation);
        let mut changed = false;
        for (name, report) in reports {
            let key = format!("{name}={}", report.version);
            for item in report
                .evidence
                .iter()
                .filter(|item| item.matches_candidate(&report.version))
            {
                if item.category == Category::Malicious {
                    changed = true;
                    self.aur_malicious
                        .entry(key.clone())
                        .or_default()
                        .insert(item.scanner, item.clone());
                } else if can_clear
                    && item.category == Category::Clean
                    && item.version.as_ref() == Some(&report.version)
                    && let Some(known) = self.aur_malicious.get_mut(&key)
                {
                    changed |= known.remove(&item.scanner).is_some();
                }
            }
        }
        self.aur_malicious.retain(|_, known| !known.is_empty());
        if changed {
            self.aur_block_generation = self.aur_block_generation.wrapping_add(1);
        }
    }

    pub fn refresh_aur_decisions(
        &mut self,
        pending: &mut Pending,
        settings: &crate::settings::Settings,
    ) {
        // An unscreened window still learns about blocks recorded by other windows.
        // An inventory without scanner results cannot invalidate their approvals.
        let assessed = settings.aur_screening || !pending.screens.is_empty();
        let saved = if assessed {
            Self::try_update(|state| state.reconcile(pending, settings))
        } else {
            Self::try_load()
        };
        match saved {
            Ok(state) => {
                self.aur_holds = state.aur_holds;
                self.aur_deferrals = state.aur_deferrals;
                self.aur_trust = state.aur_trust;
                if state.aur_block_generation >= self.aur_block_generation {
                    self.aur_malicious = state.aur_malicious;
                    self.aur_block_generation = state.aur_block_generation;
                }
            }
            Err(e) => {
                crate::warn!("AUR screening decisions could not be updated: {e}");
                if assessed {
                    self.reconcile(pending, settings);
                }
            }
        }
        self.show_malicious(pending);
    }

    pub fn show_malicious(&self, pending: &mut Pending) {
        for update in pending.updates.iter().filter(|u| u.source == Source::Aur) {
            let Some(known) = self
                .aur_malicious
                .get(&format!("{}={}", update.name, update.new))
            else {
                continue;
            };
            let report = pending
                .screens
                .entry(update.name.clone())
                .or_insert_with(|| Report::new(&update.new, vec![]));
            for item in known.values() {
                if report.evidence.contains(item) {
                    continue;
                }
                let mut retained = item.clone();
                retained.summary = format!("Previously reported: {}", retained.summary);
                report.evidence.push(retained);
            }
            report.category = Category::Malicious;
        }
    }

    pub fn apply_policies(
        &mut self,
        reports: &BTreeMap<String, Report>,
        settings: &crate::settings::Settings,
    ) {
        use crate::data::screening::Policy;
        self.aur_deferrals
            .retain(|_, c| settings.screening_policy(*c) == Policy::Defer);
        self.aur_trust
            .retain(|_, report| settings.screening_policy(report.category) == Policy::Inspect);
        for (name, report) in reports {
            if report.category == Category::Clean {
                self.aur_deferrals.remove(name);
            } else if settings.screening_policy(report.category) == Policy::Defer {
                self.aur_deferrals
                    .entry(name.clone())
                    .or_insert(report.category);
            }
        }
    }

    fn reconcile(&mut self, pending: &Pending, settings: &crate::settings::Settings) {
        self.apply_policies(&pending.screens, settings);
        self.observe_malicious(&pending.screens, pending.scan_generation);
        let complete = !pending.failed.contains(&Source::Aur);
        self.aur_trust.retain(|name, trusted| {
            !self
                .aur_malicious
                .contains_key(&format!("{name}={}", trusted.version))
                && match pending.screens.get(name) {
                    Some(report) => report == trusted,
                    None => !complete,
                }
        });
        self.aur_holds.retain(|name, _| {
            !pending.screens.get(name).is_some_and(|r| {
                !self
                    .aur_malicious
                    .contains_key(&format!("{name}={}", r.version))
                    && r.category == Category::Clean
                    && pending
                        .updates
                        .iter()
                        .any(|u| u.source == Source::Aur && u.name == *name && u.new == r.version)
            })
        });
    }

    fn read(path: &Path) -> io::Result<State> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_saphyr::from_str(&text).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e),
        }
    }

    fn load_from(path: &Path) -> State {
        Self::read(path).unwrap_or_else(|e| {
            crate::warn!("state.yaml is not used: {e}");
            State::default()
        })
    }

    fn update_at(path: &Path, change: impl FnOnce(&mut State)) -> io::Result<State> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path.with_extension("lock"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
        let mut state = Self::read(path)?;
        let before = state.clone();
        change(&mut state);
        if state == before {
            return Ok(state);
        }
        let yaml = serde_saphyr::to_string(&state).map_err(io::Error::other)?;
        crate::paths::write_atomic(path, yaml.as_bytes())?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_clear_only_for_a_clean_pending_version_and_approvals_expire() {
        use crate::data::updates;
        let report = Report::new(
            "2-1",
            vec![Evidence {
                scanner: Scanner::Wtako,
                version: Some("2-1".into()),
                category: Category::Minor,
                summary: "Yellow".into(),
                findings: vec!["Unpinned source".into()],
                url: String::new(),
            }],
        );
        let mut pending = updates::parse("aur\tpkg\t1-1\t2-1\n");
        pending.screens.insert("pkg".into(), report.clone());
        let mut state = State::default();
        state.aur_trust.insert("other".into(), report.clone());
        state.aur_holds.insert("pkg".into(), "1-1".into());
        state.reconcile(&updates::parse("failed\taur\n"), &Default::default());
        assert!(state.aur_trust.contains_key("other"));
        state.reconcile(&pending, &Default::default());
        assert!(state.aur_trust.is_empty());
        assert!(state.aur_holds.contains_key("pkg"));
        let r = pending.screens.get_mut("pkg").unwrap();
        r.category = Category::Clean;
        r.version = "1-1".into();
        state.reconcile(&pending, &Default::default());
        assert!(state.aur_holds.contains_key("pkg"));
        pending.screens.get_mut("pkg").unwrap().version = "2-1".into();
        state.reconcile(&pending, &Default::default());
        assert!(state.aur_holds.is_empty());
    }

    #[test]
    fn confirmed_findings_survive_outages_disabled_sources_and_other_clean_reports() {
        let e = |scanner, category, version: &str| Evidence {
            scanner,
            version: Some(version.into()),
            category,
            summary: "provider verdict".into(),
            findings: vec![],
            url: String::new(),
        };
        let mut state = State::default();
        let mut pending = crate::data::updates::parse("aur\tpkg\t1-1\t2-1\n");
        for (item, blocked) in [
            (e(Scanner::Wtako, Category::Malicious, "2-1"), true),
            (e(Scanner::Wtako, Category::Missing, "2-1"), true),
            (e(Scanner::Cretezy, Category::Clean, "2-1"), true),
            (e(Scanner::Wtako, Category::Clean, "1-1"), true),
            (e(Scanner::Wtako, Category::Clean, "2-1"), false),
        ] {
            pending.scan_generation = Some(state.aur_block_generation);
            pending
                .screens
                .insert("pkg".into(), Report::new("2-1", vec![item]));
            state.reconcile(&pending, &Default::default());
            assert_eq!(state.has_malicious(), blocked);
            state.show_malicious(&mut pending);
            assert_eq!(
                pending.screens["pkg"].category == Category::Malicious,
                blocked
            );
        }
    }

    #[test]
    fn legacy_blocks_apply_only_to_the_version_the_provider_identified() {
        let legacy = r#"
aur-malicious:
  pkg:
    wtako: {scanner: wtako, version: old, category: malicious, summary: black, findings: [], url: reported}
    aurwatch: {scanner: aurwatch, version: null, category: malicious, summary: unversioned, findings: [], url: unknown}
"#;
        let mut state: State = serde_saphyr::from_str(legacy).unwrap();
        assert_eq!(state.malicious_evidence("pkg", "old").count(), 1);
        assert!(!state.is_malicious("pkg", "new"));
        let mut next = crate::data::updates::parse("aur\tpkg\told\tnew\n");
        assert!(!state.blocks_pending(&next));
        state.show_malicious(&mut next);
        assert!(next.screens.is_empty());

        let e = Evidence {
            scanner: Scanner::Wtako,
            version: Some("new".into()),
            category: Category::Malicious,
            summary: "black".into(),
            findings: vec![],
            url: "reported".into(),
        };
        next.screens
            .insert("pkg".into(), Report::new("new", vec![e]));
        state.observe_malicious(&next.screens, None);
        assert!(state.blocks_pending(&next) && state.is_malicious("pkg", "old"));
        let stored = serde_saphyr::to_string(&state).unwrap();
        assert_eq!(state, serde_saphyr::from_str::<State>(&stored).unwrap());
    }

    #[test]
    fn an_older_inflight_clean_result_cannot_clear_a_newer_compromise() {
        let scores = |category| {
            BTreeMap::from([(
                "pkg".into(),
                Report::new(
                    "1-1",
                    vec![Evidence {
                        scanner: Scanner::Wtako,
                        version: Some("1-1".into()),
                        category,
                        summary: String::new(),
                        findings: vec![],
                        url: String::new(),
                    }],
                ),
            )])
        };
        let mut state = State::default();
        state.observe_malicious(&scores(Category::Malicious), Some(0));
        state.observe_malicious(&scores(Category::Clean), Some(0));
        assert!(state.has_malicious());
        state.observe_malicious(&scores(Category::Clean), Some(state.aur_block_generation));
        assert!(!state.has_malicious());
    }

    #[test]
    fn deferred_updates_wait_for_green_across_a_change_in_category() {
        use crate::data::screening::Policy;
        let mut state = State::default();
        let mut settings = crate::settings::Settings::default();
        settings.set_screening_policy(Category::Minor, Policy::Defer);
        let reports = |category| {
            BTreeMap::from([(
                "pkg".into(),
                Report::new(
                    "2-1",
                    vec![Evidence {
                        scanner: Scanner::Pkglint,
                        version: Some("2-1".into()),
                        category,
                        summary: "grade".into(),
                        findings: vec![],
                        url: String::new(),
                    }],
                ),
            )])
        };
        state.apply_policies(&reports(Category::Minor), &settings);
        state.apply_policies(&reports(Category::Missing), &settings);
        assert!(state.deferred("pkg", &settings));
        state.apply_policies(&reports(Category::Clean), &settings);
        assert!(!state.deferred("pkg", &settings));
    }

    #[test]
    fn old_wtako_approvals_expire_without_losing_other_state() {
        let old = "news-read: [first]\naur-holds: {pkg: old}\naur-trust:\n  pkg:\n    version: old\n    status: Flagged\n    summary: Yellow\n    findings: []\n    url: example\n";
        let state: State = serde_saphyr::from_str(old).unwrap();
        assert_eq!(state.news_read.unwrap(), ["first"]);
        assert!(state.aur_holds.contains_key("pkg"));
        assert!(state.aur_trust["pkg"].evidence.is_empty());
    }

    #[test]
    fn an_update_keeps_what_another_process_wrote_meanwhile() {
        let dir = std::env::temp_dir().join(format!("sm-state-{}", std::process::id()));
        let path = dir.join("state.yaml");
        let ui = State::update_at(&path, |s| s.news_read = Some(vec!["a".into()])).unwrap();
        State::update_at(&path, |s| s.notified = vec!["linux 7.2".into()]).unwrap();
        let later = State::update_at(&path, |s| {
            s.news_read.get_or_insert_with(Vec::new).push("b".into())
        })
        .unwrap();
        assert_eq!(ui.notified, Vec::<String>::new());
        assert_eq!(later.notified, ["linux 7.2"]);
        assert_eq!(later.news_read, Some(vec!["a".into(), "b".into()]));
        std::fs::write(&path, "news-read: [unclosed").unwrap();
        assert_eq!(State::load_from(&path), State::default());
        assert!(State::update_at(&path, |_| {}).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "news-read: [unclosed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The timer and the window change the file at the same moment: the second waits for the
    /// first and keeps its change.
    #[test]
    fn two_updates_at_once_keep_each_others_change() {
        let dir = std::env::temp_dir().join(format!("sm-state-lock-{}", std::process::id()));
        let path = dir.join("state.yaml");
        let slow = std::thread::spawn({
            let path = path.clone();
            move || {
                State::update_at(&path, |s| {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    s.notified = vec!["linux 7.2".into()];
                })
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let quick = State::update_at(&path, |s| s.news_read = Some(vec!["a".into()])).unwrap();
        slow.join().unwrap().unwrap();
        assert_eq!(
            quick.notified,
            ["linux 7.2"],
            "read once the first was written"
        );
        let both = State::load_from(&path);
        assert_eq!(both.notified, ["linux 7.2"]);
        assert_eq!(both.news_read, Some(vec!["a".into()]));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
