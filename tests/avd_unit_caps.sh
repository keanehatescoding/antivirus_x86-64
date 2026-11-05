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

# Both are outputs read by the scripts that source this file.
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
    return 0
}
