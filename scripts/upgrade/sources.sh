# shellcheck shell=bash

# Only package names and provider-issued numeric/hexadecimal IDs enter these URLs.
scan_source() {
    local source=${1-} name=${2-} id=${3-}
    local etag_pattern='^(W/)?"[a-zA-Z0-9._:-]+"$'
    local -a http=(curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --connect-timeout 2 --max-time 5)
    if [[ $source == aur-sleuth ]]; then
        [[ $# == 1 || ($# == 2 && $name =~ $etag_pattern && ${#name} -le 128) ]] || return 2
        [[ -z $name ]] || http+=(--header "If-None-Match: $name")
        "${http[@]}" --max-filesize 16777216 --write-out '\n%header{etag}\n%{response_code}' \
            https://mgalgs.io/aur-sleuth/_dashboard/data.json
        return
    fi
    [[ $# -ge 2 && $# -le 3 && ${#name} -le 200 && $name =~ ^[a-zA-Z0-9@_+][a-zA-Z0-9@._+-]*$ ]] || return 2
    http+=(--max-filesize 1048576)
    case "$source:${id:+id}" in
    aurwatch:) "${http[@]}" -G --data-urlencode "pkg=$name" https://aurwatch.org/api/v1/check ;;
    pkglint:) "${http[@]}" "https://jamison.lahman.dev/pkglint/package/$name.html" ;;
    aur-review:) "${http[@]}" -G --data-urlencode "search=$name" https://aur-review.com/ ;;
    aur-review:id)
        [[ $id =~ ^(packages|versions)/[0-9]{1,16}$ ]] || return 2
        if [[ $id == packages/* ]]; then id+=/versions; fi
        "${http[@]}" "https://aur-review.com/$id"
        ;;
    cretezy:) "${http[@]}" -G --data-urlencode "q=$name" https://aur-security.cretezy.com/checks ;;
    cretezy:id)
        [[ $id =~ ^[0-9a-f]{40}$ ]] || return 2
        "${http[@]}" --json "{\"packages\":[{\"package_base\":\"$name\",\"commits\":[\"$id\"]}]}" \
            https://aur-security.cretezy.com/api/v1/checks/lookup
        ;;
    *) return 2 ;;
    esac
}
