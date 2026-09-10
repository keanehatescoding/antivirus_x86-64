#!/bin/sh
set -eu
# Builds an AppImage of the GTK4 management console (userspace/av-gui)
# ONLY - not the kernel module or avd system daemon, see
# packaging/appimage/README.md and packaging/flatpak/org.hyprav.avgui.yml's
# own comment for why those can't be packaged this way. A native
# hyprav (+ hyprav-dkms) install is still required for this to do
# anything - see the top-level README's "GUI: av-gui" section.
#
# Deliberately does NOT bundle GTK4/PyGObject/Python itself (no
# linuxdeploy-plugin-gtk / linuxdeploy-plugin-python step) - doing
# that reliably for a GTK4 + PyGObject app is a well-known source of
# typelib/ABI mismatches between the bundled and host GTK stacks, and
# wasn't build-testable in this environment (no linuxdeploy or
# appimagetool available here). Since av-gui always needs a natively
# installed hyprav (avd/avctl) on the host regardless of how the GUI
# itself is packaged, requiring host GTK4+PyGObject too is consistent
# with that, not an extra burden - see usr/bin/av-gui's own comment
# (installed below from ./av-gui-launcher) for the runtime side of
# this.
#
# Build-tested end-to-end (real appimagetool, real av-gui launch out
# of the resulting AppImage via APPIMAGE_EXTRACT_AND_RUN=1 - GTK4
# initialized and rendered against the host's own GTK4/PyGObject, as
# documented above) - see .github/workflows/release.yml's
# build-appimage job, which runs this exact script in CI on every
# tagged release.
#
# Needs appimagetool on PATH (or $APPIMAGETOOL) - a pinned versioned
# release from https://github.com/AppImage/appimagetool/releases
# (CI pins the exact version + sha256 in .github/workflows/release.yml;
# the old AppImageKit `continuous` build is mutable and unverifiable,
# so don't point anyone back at it).
#
# Usage: packaging/appimage/build-appimage.sh [version]

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
APPDIR="$HERE/AppDir"
APPIMAGETOOL="${APPIMAGETOOL:-appimagetool}"

if ! command -v "$APPIMAGETOOL" >/dev/null 2>&1; then
    echo "ERROR: $APPIMAGETOOL not found on PATH." >&2
    echo "Download a versioned release from https://github.com/AppImage/appimagetool/releases" >&2
    echo "and either put it on PATH as appimagetool or set \$APPIMAGETOOL." >&2
    exit 1
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib/hyprav/av-gui" \
    "$APPDIR/usr/share/applications" \
    "$APPDIR/usr/share/metainfo" \
    "$APPDIR/usr/share/icons/hicolor/scalable/apps"

cp -r "$ROOT/userspace/av-gui/av_gui" "$APPDIR/usr/lib/hyprav/av-gui/"
find "$APPDIR/usr/lib/hyprav/av-gui/av_gui" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

install -m 0755 "$HERE/AppRun" "$APPDIR/AppRun"
install -m 0755 "$HERE/av-gui-launcher" "$APPDIR/usr/bin/av-gui"

# Desktop entry and icon need to exist BOTH at the AppDir root
# (appimagetool's own convention, used to build the embedded thumbnail
# and top-level *.desktop it expects) and under usr/share/... (so
# desktop integration tools like appimaged/AppImageLauncher, which
# read the installed AppImage's internal FS rather than just its root,
# also pick them up).
install -m 0644 "$ROOT/packaging/org.hyprav.avgui.desktop" "$APPDIR/org.hyprav.avgui.desktop"
install -m 0644 "$ROOT/packaging/org.hyprav.avgui.desktop" "$APPDIR/usr/share/applications/org.hyprav.avgui.desktop"
install -m 0644 "$ROOT/packaging/org.hyprav.avgui.metainfo.xml" "$APPDIR/usr/share/metainfo/org.hyprav.avgui.metainfo.xml"
install -m 0644 "$ROOT/packaging/icons/org.hyprav.avgui.svg" "$APPDIR/org.hyprav.avgui.svg"
install -m 0644 "$ROOT/packaging/icons/org.hyprav.avgui.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/org.hyprav.avgui.svg"

VERSION="${1:-$(cd "$ROOT" && git describe --tags --always 2>/dev/null || echo dev)}"
OUTPUT="$HERE/HyprAV-avgui-${VERSION}-x86_64.AppImage"

# --runtime-file pins the exact type2 runtime embedded in the output.
# Without it appimagetool downloads the *latest* runtime itself at
# build time, which no checksum covers (CI sets this to its verified
# copy - see .github/workflows/release.yml). Left unset for local
# builds, where appimagetool's default behavior is unchanged.
if [ -n "${APPIMAGE_RUNTIME_FILE:-}" ]; then
    ARCH=x86_64 "$APPIMAGETOOL" --runtime-file "$APPIMAGE_RUNTIME_FILE" "$APPDIR" "$OUTPUT"
else
    ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "$OUTPUT"
fi
echo "Built: $OUTPUT"
