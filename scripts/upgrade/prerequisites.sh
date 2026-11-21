# shellcheck shell=bash
# The caller supplies selected (name to version), capabilities and dependencies.

# A split package inherits each unsuffixed and architecture-specific field
# independently. An explicitly empty field removes the corresponding base values.
collect_prerequisites() {
    local base=$1 arch=$2 metadata=$3 field equals value section='' package kind key
    local name_pattern='[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*' version_pattern='[a-zA-Z0-9._+:~-]+'
    local dependency_pattern="^${name_pattern}((>=|<=|=|>|<)${version_pattern})?$"
    local provision_pattern="^${name_pattern}(=${version_pattern})?$"
    local -A fields=() packages=() seen=()
    local -a values=()
    [[ $base =~ ^$name_pattern$ && $arch =~ ^[a-zA-Z0-9_]+$ ]] || return 1
    while read -r field equals value; do
        case $field in
        pkgbase)
            [[ $equals == '=' && $value == "$base" && -z $section ]] || return 1
            section=base
            ;;
        pkgname)
            [[ $equals == '=' && $value =~ ^$name_pattern$ && -n $section && ! -v packages[$value] ]] || return 1
            section="package/$value"
            packages["$value"]=1
            ;;
        depends | makedepends | checkdepends | provides | "depends_$arch" | "makedepends_$arch" | "checkdepends_$arch" | "provides_$arch")
            [[ $equals == '=' && -n $section ]] || return 1
            key="$section/$field"
            if [[ -z $value ]]; then
                [[ ! -v fields[$key] ]] || return 1
                fields["$key"]=''
            else
                [[ ! -v fields[$key] || -n ${fields[$key]} ]] || return 1
                case $field in
                provides*) [[ $value =~ $provision_pattern ]] || return 1 ;;
                *) [[ $value =~ $dependency_pattern ]] || return 1 ;;
                esac
                fields["$key"]+="$value "
            fi
            ;;
        esac
    done <<<"$metadata"
    [[ ${#packages[@]} -gt 0 ]] || return 1
    for package in "${!packages[@]}"; do
        # shellcheck disable=SC2154
        [[ -v selected[$package] ]] || continue
        for kind in makedepends checkdepends depends provides; do
            for field in "$kind" "${kind}_$arch"; do
                key="package/$package/$field"
                [[ -v fields[$key] ]] || key="base/$field"
                read -r -a values <<<"${fields[$key]-}"
                for value in "${values[@]}"; do
                    if [[ $kind == provides ]]; then
                        # shellcheck disable=SC2034
                        capabilities["$value"]=1
                    elif [[ ! -v seen[$value] ]]; then
                        # shellcheck disable=SC2034
                        dependencies+=("$value")
                        seen["$value"]=1
                    fi
                done
            done
        done
    done
}

# Match the requested dependency against package names and virtual provisions.
# An unversioned provision can satisfy only an unversioned dependency.
dependency_offered() {
    local dependency=$1 name operator version provision comparison
    shift
    [[ $dependency =~ $dependency_pattern ]] || return 1
    name=${BASH_REMATCH[1]} operator=${BASH_REMATCH[3]} version=${BASH_REMATCH[4]}
    for provision; do
        [[ ${provision%%=*} == "$name" ]] || continue
        [[ -n $operator ]] || return 0
        [[ $provision == *=* ]] || continue
        comparison=$(vercmp "${provision#*=}" "$version") || return 1
        case "$operator/$comparison" in
        '=/0' | '>=/0' | '>=/1' | '>/1' | '<=/0' | '<=/-1' | '</-1') return 0 ;;
        esac
    done
    return 1
}

# A requirement must be installed, selected for this run, or resolvable from
# pacman's sync databases without asking the AUR helper for another recipe.
prerequisites_satisfied() {
    local dependency missing status=0 name line plan
    local dependency_pattern='^([a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*)((>=|<=|=|>|<)([a-zA-Z0-9._+:~-]+))?$'
    local -A requested=()
    local -a offers=() unresolved=() packages=()
    (($#)) || return 0
    for dependency; do
        [[ $dependency =~ $dependency_pattern ]] || return 1
        requested["$dependency"]=1
    done
    missing=$(pacman -T -- "$@") || status=$?
    case $status in
    0)
        [[ -z $missing ]]
        return
        ;;
    127) [[ -n $missing ]] || return 1 ;;
    *) return 1 ;;
    esac
    for name in "${!selected[@]}"; do offers+=("$name=${selected[$name]}"); done
    offers+=("${!capabilities[@]}")
    while IFS= read -r dependency; do
        [[ $dependency =~ $dependency_pattern && -v requested[$dependency] ]] || return 1
        dependency_offered "$dependency" "${offers[@]}" || unresolved+=("$dependency")
    done <<<"$missing"
    ((${#unresolved[@]})) || return 0

    # -Sp prepares a read-only repository transaction. It can expand group
    # names, so verify that actual packages in its plan satisfy each requirement.
    plan=$(pacman -Sp --noconfirm --print-format 'pkg %n=%v %P' -- "${unresolved[@]}" </dev/null) || return 1
    offers=()
    while IFS= read -r line; do
        [[ $line == 'pkg '* ]] || continue
        read -r -a packages <<<"${line#pkg }"
        offers+=("${packages[@]}")
    done <<<"$plan"
    for dependency in "${unresolved[@]}"; do
        dependency_offered "$dependency" "${offers[@]}" || return 1
    done
    return 0
}
