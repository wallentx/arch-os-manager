//! Selected AUR updates satisfy prerequisites without adding excluded updates.

use std::process::Command;

fn check(body: &str) {
    let source = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/upgrade/prerequisites.sh"
    );
    let output = Command::new("bash")
        .args(["--noprofile", "--norc", "-eu", "-o", "pipefail", "-c"])
        .arg(format!(
            "source \"$1\"\ndeclare -A selected=() capabilities=()\ndeclare -a dependencies=()\n{body}"
        ))
        .arg("prerequisite-test")
        .arg(source)
        .env_remove("BASH_ENV")
        .env("LC_ALL", "C.UTF-8")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn selected_names_and_provisions_satisfy_real_pacman_missing_requirements() {
    check(
        r#"
selected[codex-prerequisite-fixture-lib]=2:2.0-1
capabilities[codex-prerequisite-fixture-virtual=3]=1
capabilities[codex-prerequisite-fixture-unversioned]=1
prerequisites_satisfied 'codex-prerequisite-fixture-lib>=2:2' 'codex-prerequisite-fixture-virtual=3'
prerequisites_satisfied 'codex-prerequisite-fixture-lib>1:99' 'codex-prerequisite-fixture-virtual<=3' codex-prerequisite-fixture-unversioned
if prerequisites_satisfied 'codex-prerequisite-fixture-lib>=2:3'; then exit 1; fi
if prerequisites_satisfied 'codex-prerequisite-fixture-virtual>3'; then exit 1; fi
if prerequisites_satisfied 'codex-prerequisite-fixture-unversioned>=1'; then exit 1; fi
if prerequisites_satisfied codex-prerequisite-fixture-excluded; then exit 1; fi
prerequisites_satisfied bash
prerequisites_satisfied
"#,
    );
}

#[test]
fn split_fields_override_base_fields_and_exclude_other_architectures_and_siblings() {
    check(
        r#"
selected[chosen]=2-1
metadata='pkgbase = bundle
provides = codex-prerequisite-fixture-base=1
provides_x86_64 = codex-prerequisite-fixture-native=4
provides_aarch64 = codex-prerequisite-fixture-other-arch=5
pkgname = excluded
provides = codex-prerequisite-fixture-excluded=9
pkgname = chosen
provides = codex-prerequisite-fixture-selected=2'
collect_prerequisites bundle x86_64 "$metadata"
prerequisites_satisfied 'codex-prerequisite-fixture-selected>=2' 'codex-prerequisite-fixture-native=4'
if prerequisites_satisfied codex-prerequisite-fixture-base; then exit 1; fi
if prerequisites_satisfied codex-prerequisite-fixture-excluded; then exit 1; fi
if prerequisites_satisfied codex-prerequisite-fixture-other-arch; then exit 1; fi
capabilities=()
collect_prerequisites bundle x86_64 "$metadata
provides_x86_64 ="
if prerequisites_satisfied codex-prerequisite-fixture-native; then exit 1; fi
capabilities=()
collect_prerequisites bundle x86_64 'pkgbase = bundle
provides = codex-prerequisite-fixture-inherited=3
pkgname = chosen'
prerequisites_satisfied 'codex-prerequisite-fixture-inherited=3'
capabilities=()
collect_prerequisites chosen x86_64 'pkgbase = chosen
provides = codex-prerequisite-fixture-old=1
pkgname = chosen
provides ='
if prerequisites_satisfied codex-prerequisite-fixture-old; then exit 1; fi
"#,
    );
}

#[test]
fn selected_splits_use_effective_arch_specific_dependencies_including_empty_overrides() {
    check(
        r#"
selected[chosen]=2-1
collect_prerequisites bundle x86_64 'pkgbase = bundle
depends = replaced
depends_x86_64 = obsolete
depends_aarch64 = otherarch
makedepends = build-tool
checkdepends = never-used
checkdepends_x86_64 = native-check
pkgname = excluded
depends = from-excluded
pkgname = chosen
depends = actual>=2
depends = runtime
depends_x86_64 =
checkdepends =
checkdepends_x86_64 = new-check'
[[ ${dependencies[*]} == 'build-tool new-check actual>=2 runtime' ]]
dependencies=()
selected[excluded]=2-1
collect_prerequisites bundle x86_64 'pkgbase = bundle
depends = common
depends_x86_64 = native
pkgname = chosen
depends =
pkgname = excluded
depends_x86_64 ='
[[ ${#dependencies[@]} == 2 ]]
[[ " ${dependencies[*]} " == *' common '* && " ${dependencies[*]} " == *' native '* ]]
"#,
    );
}

#[test]
fn sync_repository_can_supply_real_and_virtual_versioned_dependencies() {
    check(
        r#"
# A private sync database keeps this test independent of mirror state and the
# machine's installed packages. pacman performs only -T and -Sp queries.
testdir=$(mktemp -d)
trap 'rm -rf -- "$testdir"' EXIT
mkdir -p "$testdir/db/sync" "$testdir/db/local" "$testdir/repo/compiler-4-1"
cp "$(pacman-conf DBPath)/local/ALPM_DB_VERSION" "$testdir/db/local/"
cat > "$testdir/repo/compiler-4-1/desc" <<'DESC'
%FILENAME%
compiler-4-1-any.pkg.tar.zst

%NAME%
compiler

%VERSION%
4-1

%ARCH%
any

%GROUPS%
tools-group

%PROVIDES%
virtual-compiler=3
virtual-tool

DESC
bsdtar -cf "$testdir/db/sync/tools.db" -C "$testdir/repo" compiler-4-1
printf '%s\n' '[options]' 'Architecture = auto' 'SigLevel = Never' '[tools]' "Server = file://$testdir/repo" > "$testdir/pacman.conf"
pacman() { command pacman --config "$testdir/pacman.conf" --dbpath "$testdir/db" "$@"; }
selected[local-build]=2-1
prerequisites_satisfied 'compiler>=4' 'virtual-compiler>=3' virtual-tool 'local-build=2-1'
if prerequisites_satisfied 'virtual-compiler>3'; then exit 1; fi
if prerequisites_satisfied 'virtual-tool>=1'; then exit 1; fi
if prerequisites_satisfied tools-group; then exit 1; fi
if prerequisites_satisfied excluded-aur-only; then exit 1; fi
"#,
    );
}

#[test]
fn malformed_metadata_and_failed_or_inconsistent_dependency_queries_fail_closed() {
    check(
        r#"
selected[chosen]=2-1
for metadata in \
    'pkgname = chosen' \
    $'pkgbase = other\npkgname = chosen' \
    $'pkgbase = bundle\npkgname = chosen\nprovides = virtual>=2' \
    $'pkgbase = bundle\npkgname = chosen\nprovides = virtual=2 extra' \
    $'pkgbase = bundle\npkgname = chosen\nprovides =\nprovides = virtual=2' \
    $'pkgbase = bundle\npkgname = chosen\npkgname = chosen'; do
    if collect_prerequisites bundle x86_64 "$metadata"; then exit 1; fi
done
if prerequisites_satisfied 'virtual>='; then exit 1; fi
if prerequisites_satisfied 'virtual:2'; then exit 1; fi
if prerequisites_satisfied 'virtual=2 extra'; then exit 1; fi
pacman() { return 1; }
if prerequisites_satisfied chosen; then exit 1; fi
pacman() { return 127; }
if prerequisites_satisfied chosen; then exit 1; fi
pacman() { printf '%s\n' unexpected; return 127; }
if prerequisites_satisfied chosen; then exit 1; fi
pacman() { printf '%s\n' chosen; return 0; }
if prerequisites_satisfied chosen; then exit 1; fi
pacman() { printf '%s\n' 'chosen>=1'; return 127; }
vercmp() { printf '%s\n' invalid; }
if prerequisites_satisfied 'chosen>=1'; then exit 1; fi
"#,
    );
}
