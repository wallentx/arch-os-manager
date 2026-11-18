//! `~/.arch-os/state.yaml`: what the program remembers between runs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use std::{io, path::Path};

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct State {
    /// An exception applies only while the candidate version and findings still match.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aur_trust: BTreeMap<String, crate::data::screening::Report>,
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

    /// Release holds only after a completed assessment for the pending version.
    /// Remove superseded approvals so an older verdict cannot reactivate one.
    pub fn refresh_aur_decisions(&mut self, pending: &crate::data::updates::Pending) {
        match Self::try_update(|state| state.reconcile(pending)) {
            Ok(state) => {
                self.aur_holds = state.aur_holds;
                self.aur_trust = state.aur_trust;
            }
            Err(e) => crate::warn!("AUR screening decisions could not be updated: {e}"),
        }
    }

    fn reconcile(&mut self, pending: &crate::data::updates::Pending) {
        use crate::data::{screening::Status, updates::Source};
        let complete = !pending.failed.contains(&Source::Aur);
        self.aur_trust
            .retain(|name, trusted| match pending.screens.get(name) {
                Some(report) => report == trusted,
                None => !complete,
            });
        self.aur_holds.retain(|name, _| {
            !pending.screens.get(name).is_some_and(|r| {
                r.status == Status::Clean
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
        use crate::data::{
            screening::{Report, Status},
            updates,
        };
        let report = Report {
            version: "2-1".into(),
            status: Status::Flagged,
            summary: "Yellow".into(),
            findings: vec!["Unpinned source".into()],
            url: String::new(),
        };
        let mut pending = updates::parse("aur\tpkg\t1-1\t2-1\n");
        pending.screens.insert("pkg".into(), report.clone());
        let mut state = State::default();
        state.aur_trust.insert("other".into(), report.clone());
        state.aur_holds.insert("pkg".into(), "1-1".into());
        state.reconcile(&updates::parse("failed\taur\n"));
        assert!(state.aur_trust.contains_key("other"));
        state.reconcile(&pending);
        assert!(state.aur_trust.is_empty());
        assert!(state.aur_holds.contains_key("pkg"));
        let r = pending.screens.get_mut("pkg").unwrap();
        r.status = Status::Clean;
        r.version = "1-1".into();
        state.reconcile(&pending);
        assert!(state.aur_holds.contains_key("pkg"));
        pending.screens.get_mut("pkg").unwrap().version = "2-1".into();
        state.reconcile(&pending);
        assert!(state.aur_holds.is_empty());
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
