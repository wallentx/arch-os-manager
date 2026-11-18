# shellcheck shell=bash
# The caller supplies associative arrays selected (name to version) and capabilities.

# Read effective provisions for selected split packages from .SRCINFO data.
# Package fields override their base field independently for each architecture.
collect_provisions() {
    local base=$1 arch=$2 metadata=$3 field equals value current='' package kind key
    local name_pattern='[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*'
    local provision_pattern='^[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*(=[a-zA-Z0-9._+:~\-]+)?$'
    local -A fields=() present=() packages=() empty=()
    [[ $base =~ ^$name_pattern$ && $arch =~ ^[a-zA-Z0-9_]+$ ]] || return 1
    while read -r field equals value; do
        case $field in
        pkgbase)
            [[ $equals == '=' && $value == "$base" && -z $current ]] || return 1
            current=$base
            ;;
        pkgname)
            [[ $equals == '=' && $value =~ ^$name_pattern$ && -n $current && ! -v packages[$value] ]] || return 1
            current=$value
            packages["$current"]=1
            ;;
        provides | "provides_$arch")
            [[ $equals == '=' && -n $current ]] || return 1
            # Distinguish the base from the identically named single package.
            if [[ -v packages[$current] ]]; then key="package/$current/$field"; else key="base/$field"; fi
            present["$key"]=1
            if [[ -z $value ]]; then
                [[ ! -v fields[$key] ]] || return 1
                empty["$key"]=1
            else
                [[ $value =~ $provision_pattern && ! -v empty[$key] ]] || return 1
                fields["$key"]+="$value "
            fi
            ;;
        esac
    done <<<"$metadata"
    [[ -n $current && ${#packages[@]} -gt 0 ]] || return 1
    local -a provisions=()
    for package in "${!packages[@]}"; do
        # selected belongs to screened(), the caller of this helper.
        # shellcheck disable=SC2154
        [[ -v selected[$package] ]] || continue
        for kind in provides "provides_$arch"; do
            key="package/$package/$kind"
            [[ -v present[$key] ]] || key="base/$kind"
            read -r -a provisions <<<"${fields[$key]-}"
            for value in "${provisions[@]}"; do
                # shellcheck disable=SC2034
                capabilities["$value"]=1
            done
        done
    done
}

# Installed packages are checked by libalpm. Selected updates can satisfy the
# remaining requirements by their own version or an explicit virtual provision.
prerequisites_satisfied() {
    local dependency missing status=0 name operator version provision offered comparison satisfied
    local dependency_pattern='^([a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*)(>=|<=|=|>|<)?([a-zA-Z0-9._+:~\-]*)$'
    local -A requested=()
    local -a offers=()
    (($#)) || return 0
    for dependency; do
        [[ $dependency =~ $dependency_pattern ]] || return 1
        [[ -z ${BASH_REMATCH[2]} && -z ${BASH_REMATCH[3]} || -n ${BASH_REMATCH[2]} && -n ${BASH_REMATCH[3]} ]] || return 1
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
        [[ -n $dependency && -v requested[$dependency] && $dependency =~ $dependency_pattern ]] || return 1
        name=${BASH_REMATCH[1]} operator=${BASH_REMATCH[2]} version=${BASH_REMATCH[3]}
        satisfied=false
        for provision in "${offers[@]}"; do
            [[ ${provision%%=*} == "$name" ]] || continue
            if [[ -z $operator ]]; then
                satisfied=true
                break
            fi
            [[ $provision == *=* ]] || continue
            offered=${provision#*=}
            comparison=$(vercmp "$offered" "$version") || return 1
            case "$operator/$comparison" in
            '=/0' | '>=/0' | '>=/1' | '>/1' | '<=/0' | '<=/-1' | '</-1')
                satisfied=true
                break
                ;;
            */-1 | */0 | */1) ;;
            *) return 1 ;;
            esac
        done
        [[ $satisfied == true ]] || return 1
    done <<<"$missing"
}
