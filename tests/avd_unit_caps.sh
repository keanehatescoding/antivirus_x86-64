# shellcheck shell=bash
# tests/avd_unit_caps.sh - sourced, not run. Defines avd_unit_wrap(),
# which reads CapabilityBoundingSet= and NoNewPrivileges= from
# packaging/avd.service and fills the array AVD_UNIT_WRAP with a setpriv
# prefix that applies the same two restrictions to a single command:
#
#   avd_unit_wrap "$REPO_ROOT/packaging/avd.service" || exit 1
#   exec "${AVD_UNIT_WRAP[@]}" "$AVD_DIR/avd" ...
#
# The end-to-end tests run avd outside systemd (virtme-ng has no systemd
# as init), so without this they would test an avd with every capability
# while the shipped unit starts it with ten. Reading the values out of the
# unit, rather than repeating them here, keeps the tests on whatever the
# unit actually ships. A root process exec'd under a bounding set ends up
# with permitted and effective = that set, which is what systemd does for
# CapabilityBoundingSet= with User=root.
#
# Also sets AVD_UNIT_CAPBND to the bounding set as /proc/<pid>/status prints
# it (16 hex digits), for checking that the wrapper took effect.
#
# It then adds the unit's SystemCallFilter= and SystemCallArchitectures=
# (avd_unit_seccomp below), so the prefix becomes
#   setpriv ... -- avd_unit_seccomp NAME... -- COMMAND
# The helper is built into AVD_UNIT_BUILD_DIR; the caller removes it.

# All are outputs read by the scripts that source this file.
# shellcheck disable=SC2034
avd_unit_wrap() {
    local unit="$1" line caps=() nnp="" c n mask=0 spec=""

    AVD_UNIT_WRAP=()
    AVD_UNIT_CAPBND=""
    if ! command -v setpriv >/dev/null 2>&1; then
        echo "FAIL: setpriv (util-linux) not found - needed to start avd under"
        echo "      the unit's CapabilityBoundingSet= and NoNewPrivileges="
        return 1
    fi
    line="$(sed -n 's/^CapabilityBoundingSet=//p' "$unit")"
    if [ -z "$line" ] || [ "$(grep -c '^CapabilityBoundingSet=' "$unit")" -ne 1 ]; then
        echo "FAIL: expected exactly one non-empty CapabilityBoundingSet= in $unit"
        return 1
    fi
    read -r -a caps <<<"$line"
    for c in "${caps[@]}"; do
        # capsh is not always installed; map names to bit numbers here.
        case "$c" in
            CAP_CHOWN) n=0 ;; CAP_DAC_OVERRIDE) n=1 ;; CAP_DAC_READ_SEARCH) n=2 ;;
            CAP_FOWNER) n=3 ;; CAP_KILL) n=5 ;; CAP_SETGID) n=6 ;;
            CAP_SETUID) n=7 ;; CAP_SETPCAP) n=8 ;; CAP_NET_ADMIN) n=12 ;;
            CAP_SYS_ADMIN) n=21 ;;
            *) echo "FAIL: avd_unit_caps.sh has no bit number for $c (add it)"
               return 1 ;;
        esac
        mask=$((mask | (1 << n)))
        c="${c#CAP_}"
        spec+=",+${c,,}"
    done
    AVD_UNIT_CAPBND="$(printf '%016x' "$mask")"
    AVD_UNIT_WRAP=(setpriv --bounding-set "-all$spec")
    nnp="$(sed -n 's/^NoNewPrivileges=//p' "$unit")"
    case "$nnp" in
        yes|true|1|on) AVD_UNIT_WRAP+=(--no-new-privs) ;;
    esac
    AVD_UNIT_WRAP+=(--)
    avd_unit_seccomp "$unit" || return 1
    return 0
}

# _avd_unit_expand NAME|@GROUP... - the syscall names systemd's groups expand
# to, one per line (systemd-analyze lists a group's member groups by name).
_avd_unit_expand() {
    local -A seen=()
    local w x
    _avd_unit_expand1() {
        [ -n "${seen[$1]:-}" ] && return 0
        seen[$1]=1
        local out
        out="$(systemd-analyze syscall-filter --no-pager "$1" 2>/dev/null)" || {
            echo "FAIL: systemd-analyze does not know the group $1" >&2
            return 1
        }
        while read -r x; do
            case "$x" in
                ''|\#*) ;;
                @*) _avd_unit_expand1 "$x" || return 1 ;;
                *) echo "$x" ;;
            esac
        done < <(tail -n +2 <<<"$out")
    }
    for w in "$@"; do
        case "$w" in
            @*) _avd_unit_expand1 "$w" || return 1 ;;
            *) echo "$w" ;;
        esac
    done
}

# avd_unit_seccomp UNIT - appends to AVD_UNIT_WRAP a helper
# (tests/avd_unit_seccomp.c, built into AVD_UNIT_BUILD_DIR, which the caller
# removes) that installs the unit's SystemCallFilter= the way systemd does
# before it execs the rest of the command. Only the shape the unit uses is
# accepted: one allowlist line first, then lines starting with "~" that take
# names out of it (systemd merges them in that order), and
# SystemCallArchitectures=native. Also sets AVD_UNIT_SYSCALLS to the number of
# names allowed.
avd_unit_seccomp() {
    local unit="$1" line first=1 allow="" deny="" names arch allowed denied
    local -a lines=()

    AVD_UNIT_SYSCALLS=0
    mapfile -t lines < <(sed -n 's/^SystemCallFilter=//p' "$unit")
    if [ "${#lines[@]}" -eq 0 ]; then
        echo "FAIL: no SystemCallFilter= in $unit"
        return 1
    fi
    for line in "${lines[@]}"; do
        if [ "$first" = 1 ]; then
            case "$line" in
                ''|'~'*) echo "FAIL: the first SystemCallFilter= in $unit must be an allowlist"
                         return 1 ;;
            esac
            allow="$line"
            first=0
        else
            case "$line" in
                '~'*) deny+=" ${line#\~}" ;;
                *) echo "FAIL: avd_unit_caps.sh handles only '~' lines after the first SystemCallFilter="
                   return 1 ;;
            esac
        fi
    done
    arch="$(sed -n 's/^SystemCallArchitectures=//p' "$unit")"
    if [ "$arch" != native ]; then
        echo "FAIL: expected SystemCallArchitectures=native in $unit, got '$arch'"
        return 1
    fi
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        echo "FAIL: systemd-analyze not found - needed to expand SystemCallFilter= groups"
        return 1
    fi
    # Expand each list on its own first: a failure inside <(...) would not
    # reach comm's exit status, and a half-expanded deny list (an unknown
    # group stops the expansion there) would test a weaker filter than the
    # unit's.
    # shellcheck disable=SC2086 # word splitting of the unit's lists is the point
    allowed="$(_avd_unit_expand $allow)" || return 1
    # shellcheck disable=SC2086
    denied="$(_avd_unit_expand $deny)" || return 1
    names="$(comm -23 <(sort -u <<<"$allowed") <(sort -u <<<"$denied"))" || return 1
    [ -n "$names" ] || { echo "FAIL: SystemCallFilter= in $unit expands to nothing"; return 1; }
    AVD_UNIT_BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/avd_unit_seccomp.XXXXXX")" || return 1
    if ! gcc -O2 -Wall -Wextra -Werror -o "$AVD_UNIT_BUILD_DIR/avd_unit_seccomp" \
            "$(dirname "${BASH_SOURCE[0]}")/avd_unit_seccomp.c" -lseccomp; then
        echo "FAIL: cannot build tests/avd_unit_seccomp.c (needs libseccomp headers)"
        rm -rf "$AVD_UNIT_BUILD_DIR"; AVD_UNIT_BUILD_DIR=""
        return 1
    fi
    mapfile -t lines <<<"$names"
    AVD_UNIT_SYSCALLS="${#lines[@]}"
    AVD_UNIT_WRAP+=("$AVD_UNIT_BUILD_DIR/avd_unit_seccomp" "${lines[@]}" --)
    return 0
}

# avd_unit_seccomp_threads PID FILTERS - checks every thread of PID for
# Seccomp 2 (filter mode) with exactly FILTERS filters stacked
# (Seccomp_filters): 1 is the unit's alone, more means avd's own filters on
# top. Prints each thread that differs, sets AVD_UNIT_THREADS to the number of
# threads looked at, returns 1 if any differed. A thread that exits while it
# is being read is skipped, not counted.
avd_unit_seccomp_threads() {
    local pid="$1" want="$2" t st mode n bad=0
    AVD_UNIT_THREADS=0
    for t in /proc/"$pid"/task/[0-9]*; do
        st="$(command cat "$t/status" 2>/dev/null)"
        [ -z "$st" ] && [ ! -d "$t" ] && continue
        AVD_UNIT_THREADS=$((AVD_UNIT_THREADS + 1))
        mode="$(sed -n 's/^Seccomp:[[:space:]]*//p' <<<"$st")"
        n="$(sed -n 's/^Seccomp_filters:[[:space:]]*//p' <<<"$st")"
        if [ "$mode" != 2 ] || [ "$n" != "$want" ]; then
            bad=1
            echo "    thread ${t##*/}: Seccomp='$mode' Seccomp_filters='$n', expected 2 and $want"
        fi
    done
    return "$bad"
}
