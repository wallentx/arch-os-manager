# shellcheck shell=bash source=../lib/lib.sh
. "${BASH_SOURCE[0]%/*}/../lib/lib.sh" || exit 1
# shellcheck source=prerequisites.sh
. "${BASH_SOURCE[0]%/*}/prerequisites.sh" || exit 1

# What the AUR would bring, or a line `failed` where it cannot be asked. The helper
# ends with 1 both when nothing is pending and when it failed, and only a failure
# says why. A package pacman ignores stays as it is.
aur_list() {
    local pending name old new rest
    scratch
    pending="$(aur -Qua 2>"${work}/errors")" || true
    if [ -s "${work}/errors" ] && [ -z "$pending" ]; then
        cat "${work}/errors" >&2
        printf 'failed\taur\n'
    fi
    while read -r name old _ new rest; do
        if [ -n "$name" ] && [[ $rest != *'[ignored]'* ]]; then
            printf 'aur\t%s\t%s\t%s\n' "$name" "$old" "$new"
        fi
    done <<<"$pending"
}

# What an update would bring: repo, aur or flatpak, the name, the version now and the
# one to come, for Flatpak then the name it shows and the branch. The AUR or Flatpak,
# where it cannot be asked, is a line `failed` and its name, so the others still count.
# Mirrors out of reach fail the whole check.
op_list() {
    # checkupdates syncs a copy of the databases, so nothing half-synced is
    # left, and ends with 2 when nothing is pending. Two at once, as the timer
    # and the interface may run, share that copy. The AUR and Flatpak are asked
    # beside it and told after it, in this order.
    local status=0 repo
    scratch
    touch "${work}/aur" "${work}/flatpak"
    if [ -n "$SM_AUR" ]; then aur_list >"${work}/aur" 3>&- & fi
    if [ "$SM_FLATPAK" = on ]; then flatpak_list >"${work}/flatpak" 3>&- & fi
    repo="$(flock --wait 100 "${TMPDIR:-/tmp}/checkup-db-${UID}.lock" checkupdates)" || status=$?
    wait
    case "$status" in
    0) while read -r name old _ new; do printf 'repo\t%s\t%s\t%s\n' "$name" "$old" "$new"; done <<<"$repo" ;;
    2) ;;
    *) exit 10 ;;
    esac
    cat "${work}/aur" "${work}/flatpak"
}

# What Flatpak would bring. A version is often missing or unchanged, a commit and
# a name never, and read collapses empty fields between tabs, so the version comes
# last. An app without a name of its own gets the end of its id from Flatpak, as
# Compat.i386 is i386. An id pending in two branches, as a runtime may be, carries
# its branch.
flatpak_list() {
    local installed apps app arch branch commit title version ref old new name
    local -A versions commits titles pending_in
    if ! installed="$(flatpak list --columns=application,arch,branch,active,name,version)" ||
        ! apps="$(flatpak remote-ls --updates --columns=application,arch,branch,commit,version)"; then
        printf 'failed\tflatpak\n'
        return 0
    fi
    while IFS=$'\t' read -r app arch branch commit title version; do
        versions["$app/$arch/$branch"]="$version"
        commits["$app/$arch/$branch"]="$commit"
        titles["$app/$arch/$branch"]="$title"
    done <<<"$installed"
    while IFS=$'\t' read -r app _; do
        if [ -n "$app" ]; then pending_in["$app"]=$((${pending_in["$app"]:-0} + 1)); fi
    done <<<"$apps"
    while IFS=$'\t' read -r app arch branch commit version; do
        if [ -z "$app" ]; then continue; fi
        ref="$app/$arch/$branch"
        old="${versions[$ref]-}" new="$version"
        if [ -z "$old" ] || [ -z "$new" ] || [ "$old" = "$new" ]; then
            old="${commits[$ref]-}" new="$commit"
        fi
        name="$app"
        if [ "${pending_in[$app]}" -gt 1 ]; then name="${app}//${branch}"; fi
        printf 'flatpak\t%s\t%s\t%s\t%s\t%s\n' "$name" "$old" "$new" "${titles[$ref]-}" "$branch"
    done <<<"$apps"
}

# Waits the seconds given at most while an upgrade of this user runs, as the
# update indicator checks a few seconds after pacman, while Flatpak may still
# update. flock ends with 1 when the time runs out.
op_idle() {
    local lock status=0
    lock="$(run_lock)" || return 0
    flock --wait "$1" "$lock" true || status=$?
    case "$status" in
    0) ;;
    1) exit 12 ;;
    *) false ;;
    esac
}

# Scanner answers are data. Names remain a single encoded query parameter.
op_audit() {
    [[ $# == 1 && $1 =~ ^[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*(,[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*)*$ ]] || exit 14
    curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
        --connect-timeout 3 --max-time 7 --max-filesize 2097152 \
        --get --data-urlencode "names=$1" https://aur-audit.wtako.net/package-analysis
}

# Helpers build these local checkouts directly. Keep each upstream tracking branch
# at the inspected commit even if the helper refreshes it before building.
screened() {
    local name version base pending status=0 old arrow new rest dir
    local -A selected=() available=() bases=() selected_bases=() capabilities=()
    local -a dirs=() ignored=()
    local extra_output=false
    (($# > 0 && $# % 3 == 0)) || exit 14
    while (($#)); do
        name=$1 version=$2 base=$3
        [[ $name =~ ^[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*$ &&
            $base =~ ^[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*$ &&
            $version =~ ^[a-zA-Z0-9._+:~\-]+$ && ! -v selected[$name] ]] || exit 14
        [[ ! -v bases[$base] || ${bases[$base]} == "$version" ]] || exit 14
        selected["$name"]=$version
        selected_bases["$name"]=$base
        bases["$base"]=$version
        shift 3
    done
    [[ -n $SM_AUR ]] || exit 17
    pending=$(flock --wait 100 "${TMPDIR:-/tmp}/checkup-db-${UID}.lock" checkupdates) || status=$?
    case $status in
    0) exit 15 ;;
    2) [[ -z $pending ]] || exit 15 ;;
    *) exit 10 ;;
    esac
    scratch
    status=0
    pending=$(aur -Qua 2>"$work/errors") || status=$?
    if ((status > 1)) || [[ -s $work/errors ]]; then
        cat "$work/errors" >&2
        exit 17
    fi
    while read -r name old arrow new rest; do
        [[ -n $name ]] || continue
        [[ $name =~ ^[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*$ && $arrow == '->' && -n $new ]] || exit 17
        if [[ $rest == *'[ignored]'* ]]; then
            ignored+=(--ignore "$name")
        elif [[ -v selected[$name] ]]; then
            available["$name"]=$new
        else
            ignored+=(--ignore "$name")
        fi
    done <<<"$pending"
    for name in "${!selected[@]}"; do
        [[ ${available[$name]-} == "${selected[$name]}" ]] || exit 14
    done
    # Local build mode can target every output of a split recipe.
    local metadata field equals value pkgver pkgrel epoch current actual_base arch
    local -a dependencies=()
    local -A seen=()
    arch=$(uname -m)
    for base in "${!bases[@]}"; do
        dir="$work/recipes/$base"
        git -c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.https.allow=always \
            clone --quiet --depth 1 --single-branch --no-tags -- "https://aur.archlinux.org/$base.git" "$dir" || exit 19
        git -C "$dir" remote set-url origin . || exit 19
        [[ -f $dir/.SRCINFO && ! -L $dir/.SRCINFO && -f $dir/PKGBUILD && ! -L $dir/PKGBUILD ]] || exit 19
        metadata=$(<"$dir/.SRCINFO")
        dirs+=("$dir")
        pkgver='' pkgrel='' epoch='' current='' actual_base=''
        while read -r field equals value; do
            [[ $equals == '=' ]] || continue
            case $field in
            pkgbase) actual_base=$value ;;
            pkgver) pkgver=$value ;;
            pkgrel) pkgrel=$value ;;
            epoch) epoch=$value ;;
            pkgname)
                [[ $value =~ ^[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*$ ]] || exit 19
                current=$value
                if [[ ! -v selected[$current] ]]; then
                    extra_output=true
                elif [[ ${selected_bases[$current]} != "$base" ]]; then
                    exit 19
                fi
                seen["$current"]=1
                ;;
            depends | makedepends | checkdepends | "depends_$arch" | "makedepends_$arch" | "checkdepends_$arch")
                if [[ -z $current || -v selected[$current] ]]; then
                    [[ $value =~ ^[a-zA-Z0-9@_+][a-zA-Z0-9@._+:~\<\>\=\-]*$ ]] || exit 19
                    dependencies+=("$value")
                fi
                ;;
            esac
        done <<<"$metadata"
        [[ $actual_base == "$base" && -n $pkgver && -n $pkgrel ]] || exit 19
        version=$pkgver-$pkgrel
        [[ -z $epoch || $epoch == 0 ]] || version=$epoch:$version
        [[ $version == "${bases[$base]}" ]] || exit 14
        collect_provisions "$base" "$arch" "$metadata" || exit 19
    done
    for name in "${!selected[@]}"; do
        [[ -v seen[$name] ]] || exit 19
    done
    if "$extra_output"; then exit 20; fi
    if ((${#ignored[@]} && ${#dependencies[@]})); then
        prerequisites_satisfied "${dependencies[@]}" || exit 18
    fi
    step aur
    if asks || [[ ${SM_AUR_REVIEW:-on} != off ]]; then
        # In local build mode the helpers may skip their own recipe review.
        printf 'terminal\ton\n' >&3
        for dir in "${dirs[@]}"; do
            printf '\n%s\n' "${dir##*/}"
            git -C "$dir" --no-pager show --no-ext-diff --no-textconv --format= HEAD | cat -v
        done
        printf 'Build the displayed AUR recipes? [y/N] '
        local answer
        if ! IFS= read -r answer || [[ ${answer,,} != @(y|yes) ]]; then
            printf 'terminal\toff\n' >&3
            exit 21
        fi
        printf 'terminal\toff\n' >&3
    fi
    aur_sync -Bi "${ignored[@]}" -- "${dirs[@]}"
}

# Repositories first, then what is built on top of them. A failing AUR helper
# leaves Flatpak still to update. It also fails where nothing is left to do and
# the AUR is out of reach, so what it left decides the end.
op_run() {
    local aur=0 yes mode=${1:-all}
    case $mode in
    screened)
        shift
        screened "$@"
        return
        ;;
    system) [[ $# == 1 ]] || exit 14 ;;
    all)
        [[ $# == 0 ]] || exit 14
        [[ ${SM_AUR_SCREENING:-off} != on ]] || exit 16
        ;;
    *) exit 14 ;;
    esac
    step repo
    sudo pacman -Syu
    if [[ $mode == all && -n $SM_AUR ]]; then
        step aur
        aur_sync -Sua || aur=$?
    fi
    if [ "$SM_FLATPAK" = on ]; then
        step flatpak
        if asks; then yes=(); else yes=(--assumeyes --noninteractive); fi
        flatpak update "${yes[@]}"
    fi
    if [ "$aur" -ne 0 ]; then
        # A helper that no longer starts, as after a pacman update until it is rebuilt, ends
        # with its own status, so its error names the cause.
        if ! aur --version >/dev/null 2>&1; then exit "$aur"; fi
        case "$(aur_list)" in
        '') ;;
        failed*) exit 13 ;;
        *) exit 11 ;;
        esac
    fi
}

operation "$@"
