//! Guard resolution may block on the AUR after the selected packages were inspected.

use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use system_manager::{
    data::{
        screening::{self, Category, Policy, Scanner},
        updates,
    },
    settings::Settings,
    state::State,
};

#[test]
fn authorization_changes_during_guard_lookup_prevent_installation() {
    if let Some(home) = std::env::var_os("SM_AUTHORIZATION_FIXTURE") {
        assert_eq!(Some(&home), std::env::var_os("SM_HOME").as_ref());
        verify_fixture(Path::new(&home));
        return;
    }

    // Isolate the process-wide settings path and transport used by real verify() calls.
    let temp = Command::new("mktemp")
        .args(["-d", "-t", "sm-authorization.XXXXXXXX"])
        .output()
        .unwrap();
    assert!(temp.status.success());
    let dir = Path::new(std::str::from_utf8(&temp.stdout).unwrap().trim_end());
    let curl = dir.join("curl");
    fs::write(&curl, r#"#!/bin/bash
set -eu
for arg; do
    case $arg in
    'arg[]=target') printf '%s\n' '{"type":"multiinfo","results":[{"Name":"target","PackageBase":"target","Version":"2-1"}]}'; exit 0 ;;
    'names=target') printf '%s\n' '{"packages":{"target":{"packageName":"target","status":"scanned","version":"2-1","blackFlags":[],"redFlags":[],"yellowFlags":["Inspect this finding"]}}}'; exit 0 ;;
    'arg[]=remembered')
        for file in settings state; do
            if [[ -f $SM_HOME/$file.next ]]; then mv -- "$SM_HOME/$file.next" "$SM_HOME/$file.yaml"; fi
        done
        touch "$SM_HOME/queried"
        printf '%s\n' '{"type":"multiinfo","results":[]}'
        exit 0 ;;
    esac
done
exit 1
"#).unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "authorization_changes_during_guard_lookup_prevent_installation",
            "--nocapture",
        ])
        .env_clear()
        .env("SM_AUTHORIZATION_FIXTURE", dir)
        .env("HOME", dir)
        .env("SM_HOME", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env(
            "PATH",
            std::env::join_paths([dir, Path::new("/usr/bin")]).unwrap(),
        )
        .output()
        .unwrap();
    fs::remove_dir_all(dir).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verify_fixture(dir: &Path) {
    let mut settings = Settings {
        aur_screening: true,
        ..Settings::default()
    };
    for scanner in Scanner::ALL {
        settings.set_scanner_enabled(scanner, scanner == Scanner::Wtako);
    }
    let selected = screening::lookup(
        &updates::parse("aur\ttarget\t1-1\t2-1\n").updates,
        &settings,
    );
    assert_eq!(selected["target"].category, Category::Minor);
    let mut blocked = selected["target"].evidence[0].clone();
    blocked.category = Category::Malicious;
    for change in ["unchanged", "revoke", "hold", "block"] {
        settings.save().unwrap();
        let mut state = State::try_update(|s| {
            s.aur_holds.clear();
            s.aur_trust = selected.clone();
            s.aur_malicious.insert(
                "remembered=2-1".into(),
                BTreeMap::from([(Scanner::Wtako, blocked.clone())]),
            );
        })
        .unwrap();
        match change {
            "revoke" | "hold" => {
                if change == "revoke" {
                    state.aur_trust.clear();
                } else {
                    state.aur_holds.insert("target".into(), "2-1".into());
                }
                fs::write(
                    dir.join("state.next"),
                    serde_saphyr::to_string(&state).unwrap(),
                )
                .unwrap();
            }
            "block" => {
                let mut policy = settings.clone();
                policy.set_screening_policy(Category::Minor, Policy::Block);
                fs::write(
                    dir.join("settings.next"),
                    serde_saphyr::to_string(&policy).unwrap(),
                )
                .unwrap();
            }
            _ => {}
        }
        let result = screening::verify(&selected);
        assert!(
            dir.join("queried").exists(),
            "guard lookup must run for {change}"
        );
        fs::remove_file(dir.join("queried")).unwrap();
        assert_eq!(
            result.is_ok(),
            change == "unchanged",
            "{change}: {result:?}"
        );
    }
    system_manager::script::cleanup();
}
