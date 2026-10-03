# shellcheck shell=bash
# tests/avd_guard.sh - sourced, not run. Defines avd_guard(), which
# refuses to continue while some other avd could talk to the module a
# test is about to load.
#
# The kernel accepts one registered daemon (a second AV_C_REGISTER gets
# -EBUSY, see av/netlink_chan.c). An installed avd.service retries every
# few seconds until av.ko appears, so when a test insmods the module the
# system daemon can win the registration: the test's own avd then exits
# with "Object busy", and verdicts come from the system daemon's rules
# instead of the test's. Fail up front with the fix instead of letting a
# section hang or fail confusingly halfway through.

avd_guard() {
    local state pids

    if command -v systemctl >/dev/null 2>&1; then
        # is-active prints the state and exits non-zero for anything
        # but "active"; "activating" covers the Restart=on-failure loop
        # between attempts, when no avd process exists yet.
        state="$(systemctl is-active avd.service 2>/dev/null || true)"
        case "$state" in
            active|activating|deactivating|reloading|refreshing)
                echo "FAIL: avd.service is $state - it would race this test's avd"
                echo "      for the kernel registration. Stop it for the run:"
                echo "        systemctl stop avd.service"
                return 1
                ;;
        esac
    fi

    pids="$(pgrep -x avd 2>/dev/null | tr '\n' ' ' || true)"
    if [ -n "$pids" ]; then
        echo "FAIL: avd is already running (pid ${pids% }) - it would race this"
        echo "      test's avd for the kernel registration. Stop it first."
        return 1
    fi
    return 0
}
