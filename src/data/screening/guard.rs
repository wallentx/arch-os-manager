//! Bind AUR runs to the displayed candidates and the versioned blocks on disk.

use super::{package_info, package_name, rejected};
use crate::data::aur::Package;
use crate::{script::Failure, settings::Settings, state::State};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// A disabled scanner can still have a remembered confirmed release. Upgrade
/// only the versions the user saw, using the same local recipes as a screened run.
pub fn bulk(candidates: &[(String, String)]) -> Result<Vec<String>, Failure> {
    let (settings, error) = Settings::load();
    if error.is_some() || settings.aur_screening {
        return Err(rejected());
    }
    if candidates.is_empty() {
        return Ok(vec!["system".into()]);
    }
    if candidates
        .iter()
        .any(|(name, version)| !package_name(name) || version.is_empty())
    {
        return Err(rejected());
    }
    let mut packages = Vec::new();
    for batch in candidates.chunks(24) {
        packages.extend(package_info(batch, Duration::from_secs(10))?);
    }
    let mut args = vec!["guarded".into()];
    for (name, version) in candidates {
        let mut rows = packages.iter().filter(|p| p.name == *name);
        let pkg = rows.next().ok_or_else(rejected)?;
        if rows.next().is_some()
            || pkg.version != *version
            || !package_name(name)
            || !package_name(&pkg.package_base)
        {
            return Err(rejected());
        }
        args.extend([name.clone(), version.clone(), pkg.package_base.clone()]);
    }
    let state = State::try_load().map_err(|_| rejected())?;
    finalize(args, &state, &packages)
}

/// Unknown or currently published blocked releases can enter a transaction
/// through new dependencies. In that case only installed or selected packages
/// may supply its prerequisites. An old version no longer offered by the AUR
/// does not impose that restriction.
pub(super) fn finalize(
    args: Vec<String>,
    state: &State,
    packages: &[Package],
) -> Result<Vec<String>, Failure> {
    if !state.has_malicious() && args.first().is_some_and(|s| s == "screened") {
        return Ok(args);
    }
    let mut releases: BTreeMap<_, _> = packages
        .iter()
        .map(|p| {
            (
                p.name.clone(),
                Some((p.package_base.clone(), p.version.clone())),
            )
        })
        .collect();
    let blocked_names: BTreeSet<_> = state
        .aur_malicious
        .keys()
        .filter_map(|key| key.split_once('=').map(|(n, _)| n))
        .filter(|n| package_name(n) && !releases.contains_key(*n))
        .collect();
    let blocked_names: Vec<_> = blocked_names
        .into_iter()
        .map(|n| (n.to_owned(), String::new()))
        .collect();
    let until = Instant::now() + Duration::from_secs(10);
    for batch in blocked_names.chunks(24) {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match package_info(batch, remaining) {
            Ok(rows) => {
                let mut seen = BTreeSet::new();
                if rows.iter().any(|p| {
                    !batch.iter().any(|(n, _)| n == &p.name)
                        || !seen.insert(&p.name)
                        || !package_name(&p.package_base)
                        || p.version.is_empty()
                }) {
                    break;
                }
                for (n, _) in batch {
                    releases.insert(n.clone(), None);
                }
                for p in rows {
                    releases.insert(p.name, Some((p.package_base, p.version)));
                }
            }
            Err(_) => break,
        }
    }
    bound_plan(args, state, &releases)
}

fn bound_plan(
    mut args: Vec<String>,
    state: &State,
    releases: &BTreeMap<String, Option<(String, String)>>,
) -> Result<Vec<String>, Failure> {
    let mut strict = false;
    for key in state.aur_malicious.keys() {
        let (name, version) = key.split_once('=').ok_or_else(rejected)?;
        let release = releases.get(name);
        let base = release
            .and_then(|r| r.as_ref())
            .filter(|(_, current)| current == version)
            .map(|(base, _)| base.as_str());
        if args[1..]
            .chunks_exact(3)
            .any(|t| t[1] == version && (t[0] == name || t[2] == name || base == Some(&t[2])))
        {
            return Err(rejected());
        }
        match release {
            None => strict = true, // No authoritative AUR response.
            Some(Some((_, current))) if current == version => strict = true,
            _ => {}
        }
    }
    args.splice(
        1..1,
        [
            "--blocks".into(),
            state.aur_block_generation.to_string(),
            if strict { "strict" } else { "clear" }.into(),
        ],
    );
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::screening::{Category, Evidence, Report, Scanner};

    #[test]
    fn current_or_unresolved_blocks_guard_dependencies_and_share_split_bases() {
        let saved = Report::new(
            "2-1",
            vec![Evidence {
                scanner: Scanner::Wtako,
                version: Some("2-1".into()),
                category: Category::Malicious,
                summary: "Black flag".into(),
                findings: vec![],
                url: String::new(),
            }],
        );
        let mut state = State::default();
        state.observe_malicious(&BTreeMap::from([("blocked".into(), saved)]), None);
        let plan = |base: &str, v: &str| ["guarded", "good", v, base].map(String::from).to_vec();
        let current = BTreeMap::from([("blocked".into(), Some(("common".into(), "2-1".into())))]);
        let newer = BTreeMap::from([("blocked".into(), Some(("common".into(), "3-1".into())))]);
        assert!(bound_plan(plan("common", "2-1"), &state, &current).is_err());
        assert_eq!(
            bound_plan(plan("other", "2-1"), &state, &current).unwrap()[3],
            "strict"
        );
        assert_eq!(
            bound_plan(plan("common", "3-1"), &state, &newer).unwrap()[3],
            "clear"
        );
        // The blocked 2-1 release cannot acquire a new sibling via its
        // package's current 3-1 base.
        assert_eq!(
            bound_plan(plan("common", "2-1"), &state, &newer).unwrap()[3],
            "clear"
        );
        assert_eq!(
            bound_plan(plan("other", "2-1"), &state, &BTreeMap::new()).unwrap()[3],
            "strict"
        );
        assert_eq!(
            bound_plan(
                plan("other", "2-1"),
                &state,
                &BTreeMap::from([("blocked".into(), None)])
            )
            .unwrap()[3],
            "clear"
        );
    }
}
