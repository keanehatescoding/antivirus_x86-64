# AppImage: hyprav-gui

Packages the GTK4 management console (`userspace/av-gui`) only - same
scope restriction as `packaging/flatpak/`, and for the same reason:
the kernel module and the privileged `avd` system daemon aren't
userspace apps a bundling format can contain. Install `hyprav` +
`hyprav-dkms` natively first (Arch/Debian/Fedora under `packaging/`);
this AppImage is a thin client on top of that installation. See the
top-level README's "GUI: av-gui" section for what av-gui actually
does.

## What's bundled, and what isn't

Only `userspace/av-gui/av_gui` (the Python package) is bundled. GTK4,
PyGObject, and Python itself are **not** vendored into the AppImage -
`usr/bin/av-gui` (installed from `./av-gui-launcher`) runs against
whatever `python3` + GTK4 bindings the host already has, and fails
with the same friendly `checkdeps`-style message
`userspace/av-gui/Makefile` gives if they're missing.

This is a deliberate scope call, not a shortcut: reliably bundling a
GTK4 + PyGObject stack inside an AppImage (via
`linuxdeploy-plugin-gtk`/`linuxdeploy-plugin-python`) is a well-known
source of typelib/ABI mismatches between the bundled and host GTK
versions, and wasn't build-testable in the environment this was
written in (no `linuxdeploy`/`appimagetool` available there). Since
av-gui always needs a *natively installed* `hyprav` (avd + avctl) on
the host regardless of how the GUI itself is packaged, requiring host
GTK4+PyGObject too is consistent with that existing dependency, not an
extra burden - it's the same `python-gobject`/`gtk4` (Arch),
`python3-gi`/`gir1.2-gtk-4.0` (Debian), or `python3-gobject`/`gtk4`
(Fedora) the native packages already declare.

`av_gui/host_exec.py`'s Flatpak-sandbox detection
(`/.flatpak-info`) is a no-op here - an AppImage isn't sandboxed, so
`pkexec`/`avctl` get invoked directly, same as a native install.

## Build

Build-tested end-to-end: `appimagetool` produced a working AppImage
and running it (`APPIMAGE_EXTRACT_AND_RUN=1 ./HyprAV-avgui-*.AppImage`,
needed where FUSE isn't available - see `.github/workflows/release.yml`)
actually launched av-gui against the host's GTK4. Also built on every
`appimagetool` on `PATH` (or `$APPIMAGETOOL`) — use a versioned release
from <https://github.com/AppImage/appimagetool/releases> (CI pins 1.9.1
plus its sha256 in `.github/workflows/release.yml`; avoid AppImageKit's
mutable `continuous` build — it has no stable checksum to verify).

```bash
packaging/appimage/build-appimage.sh          # version defaults to `git describe`
# or: packaging/appimage/build-appimage.sh 1.2.3
./packaging/appimage/HyprAV-avgui-*-x86_64.AppImage
```
