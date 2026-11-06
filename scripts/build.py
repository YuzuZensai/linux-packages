#!/usr/bin/env python3
"""Repackage checksum-pinned AppImages without executing their runtimes."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
ARCHITECTURES = {"x86_64": ("amd64", 62), "aarch64": ("arm64", 183)}


def run(*args, **kwargs):
    try:
        return subprocess.run([str(arg) for arg in args], check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        if error.stderr:
            sys.stderr.write(error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr)
        raise


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def package_identity(app, config):
    inputs = {"app": app, "maintainer": config["maintainer"], "builder": digest(Path(__file__))}
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def relative_path(value):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"Expected a relative path: {value}")
    return path


def load_app(path):
    app = json.loads(Path(path).read_text())
    for field in ("name", "executable"):
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", app[field]):
            raise ValueError(f"Invalid {field}")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*(?:[+~][a-zA-Z0-9.]+)?", app["version"]):
        raise ValueError("Use a numeric release version. For prerelease versions, use ~ as the separator.")
    if type(app["revision"]) is not int or app["revision"] < 1:
        raise ValueError("revision must be a positive integer")
    for field in ("title", "description", "homepage", "license", "window_class"):
        if not app[field] or "\n" in app[field] or "\r" in app[field]:
            raise ValueError(f"Invalid {field}")
    for value in [app["appimage_directory"], app["icon"], app["license_file"], *app["remove"],
                  *([app["sandbox"]] if app.get("sandbox") else [])]:
        relative_path(value)
    for value in app["categories"] + app["protocols"]:
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.-]*", value):
            raise ValueError(f"Invalid desktop metadata: {value}")
    for architecture, asset in app["assets"].items():
        if architecture not in ARCHITECTURES:
            raise ValueError(f"Unsupported architecture: {architecture}")
        if not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]):
            raise ValueError("Each asset needs a pinned SHA-256")
        if not asset["url"].startswith("https://github.com/"):
            raise ValueError("Assets must use HTTPS GitHub release URLs")
    for kind in ("arch", "deb"):
        for dependency in app["dependencies"][kind]:
            if not dependency or any(c in dependency for c in "\r\n"):
                raise ValueError("Invalid dependency")
    return app


def download(asset, cache):
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / (asset["sha256"] + ".AppImage")
    if destination.exists() and digest(destination) == asset["sha256"]:
        return destination
    temporary = destination.with_suffix(".download")
    try:
        request = urllib.request.Request(asset["url"], headers={"User-Agent": "yuzu-linux-packages"})
        with urllib.request.urlopen(request, timeout=120) as source, temporary.open("wb") as target:
            shutil.copyfileobj(source, target)
        if digest(temporary) != asset["sha256"]:
            raise ValueError(f"Checksum mismatch: {asset['url']}")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def squashfs_offset(path, architecture):


    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if header[:6] != b"\x7fELF\x02\x01" or header[8:11] != b"AI\x02":
            raise ValueError("Expected a little-endian ELF64 type-2 AppImage")
        machine = struct.unpack_from("<H", header, 18)[0]
        if machine != ARCHITECTURES[architecture][1]:
            raise ValueError("AppImage architecture does not match its manifest")
        table = struct.unpack_from("<Q", header, 40)[0]
        entry_size, entries = struct.unpack_from("<HH", header, 58)
        offset = table + entry_size * entries
        if not table or not entries or offset >= Path(path).stat().st_size:
            raise ValueError("Invalid AppImage section table")
        stream.seek(offset)
        if stream.read(4) != b"hsqs":
            raise ValueError("No SquashFS image after the ELF section table")
        return offset


def validate_tree(root):

    for path in root.rglob("*"):
        if path.is_symlink():
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"Symlink escapes the application: {path}")
        elif not (path.is_file() or path.is_dir()):
            raise ValueError(f"Unsupported special file: {path}")


def write_file(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def stage(app, architecture, asset, work):
    if digest(asset) != app["assets"][architecture]["sha256"]:
        raise ValueError("The AppImage checksum does not match the manifest. Extraction was stopped.")
    image = work / "appimage"
    offset = squashfs_offset(asset, architecture)
    run("unsquashfs", "-no-progress", "-no-xattrs", "-processors", "2",
        "-o", offset, "-d", image, asset, stdout=subprocess.DEVNULL)
    validate_tree(image)
    payload = image / relative_path(app["appimage_directory"])
    executable = payload / app["executable"]
    with executable.open("rb") as stream:
        header = stream.read(20)
    if header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != ARCHITECTURES[architecture][1]:
        raise ValueError("Application executable architecture does not match its manifest")
    root = work / "root"
    destination = root / "opt" / app["name"]
    shutil.copytree(payload, destination, symlinks=True)
    validate_tree(destination)

    for value in app["remove"]:
        path = destination / relative_path(value)
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
    for path in destination.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    if app.get("sandbox"):
        (destination / app["sandbox"]).chmod(0o4755)
    command = f"/opt/{app['name']}/{app['executable']}"
    write_file(root / "usr/bin" / app["name"],
               f'#!/bin/sh\nunset APPIMAGE APPDIR\nexec {shlex.quote(command)} "$@"\n', 0o755)
    icon = image / relative_path(app["icon"])
    icon_bytes = icon.read_bytes()
    if icon_bytes[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("The manifest icon must be a PNG")
    width, height = struct.unpack_from(">II", icon_bytes, 16)
    icon_target = root / f"usr/share/icons/hicolor/{width}x{height}/apps/{app['name']}.png"
    icon_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(icon, icon_target)
    license_target = root / f"usr/share/licenses/{app['name']}/LICENSE"
    license_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(destination / app["license_file"], license_target)
    desktop = (
        f"[Desktop Entry]\nType=Application\nName={app['title']}\n"
        f"Comment={app['description']}\nExec=/usr/bin/{app['name']} %U\n"
        f"Icon={app['name']}\nTerminal=false\nStartupWMClass={app['window_class']}\n"
        f"Categories={';'.join(app['categories'])};\n"
    )
    if app["protocols"]:
        desktop += "MimeType=" + ";".join(f"x-scheme-handler/{p}" for p in app["protocols"]) + ";\n"
    write_file(root / f"usr/share/applications/{app['name']}.desktop", desktop)
    return root


def build_arch(app, architecture, root, work, output, maintainer):
    output.mkdir(parents=True, exist_ok=True)
    def array(values):
        return "(" + " ".join(shlex.quote(v) for v in values) + ")"
    recipe = (
        f"pkgname={shlex.quote(app['name'])}\npkgver={shlex.quote(app['version'])}\n"
        f"pkgrel={app['revision']}\npkgdesc={shlex.quote(app['description'])}\n"
        f"arch={array([architecture])}\nurl={shlex.quote(app['homepage'])}\n"
        f"license={array([app['license']])}\ndepends={array(app['dependencies']['arch'])}\n"
        "options=('!strip' '!debug' '!lto')\n"
        'package() { cp -a --no-preserve=ownership "$startdir/root/." "$pkgdir/"; }\n'
    )
    write_file(work / "PKGBUILD", recipe)
    config = work / "makepkg.conf"
    write_file(config, "source /etc/makepkg.conf\n"
               f"CARCH={shlex.quote(architecture)}\nPACKAGER={shlex.quote(maintainer)}\n"
               f"PKGDEST={shlex.quote(str(output.resolve()))}\n"
               "PKGEXT='.pkg.tar.zst'\nCOMPRESSZST=(zstd -c -T2 -6)\n"
               "BUILDENV=(!distcc !color !ccache !check !sign)\n")
    run("makepkg", "--config", config, "--nodeps", "--nocheck", "--noconfirm", "--nosign", cwd=work)
    path = output / f"{app['name']}-{app['version']}-{app['revision']}-{architecture}.pkg.tar.zst"
    if not path.is_file():
        raise ValueError("makepkg did not produce the expected package")
    return path


def build_deb(app, architecture, root, output, maintainer):
    output.mkdir(parents=True, exist_ok=True)
    deb_arch = ARCHITECTURES[architecture][0]
    size = sum(p.lstat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())
    control = (
        f"Package: {app['name']}\nVersion: {app['version']}-{app['revision']}\n"
        f"Architecture: {deb_arch}\nMaintainer: {maintainer}\n"
        f"Installed-Size: {(size + 1023) // 1024}\nSection: devel\nPriority: optional\n"
        f"Depends: {', '.join(app['dependencies']['deb'])}\n"
        f"Homepage: {app['homepage']}\nDescription: {app['description']}\n"
    )
    write_file(root / "DEBIAN/control", control)
    path = output / f"{app['name']}_{app['version']}-{app['revision']}_{deb_arch}.deb"
    run("dpkg-deb", "--root-owner-group", "-Zxz", "-z6", "--build", root, path)
    shutil.rmtree(root / "DEBIAN")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", help="Build only this app. By default, build all apps.")
    parser.add_argument("--arch", choices=ARCHITECTURES, help="Default: every available architecture")
    parser.add_argument("--format", choices=("arch", "deb", "all"), default="all")
    parser.add_argument("--check", action="store_true", help="Validate manifests without downloading/building")
    args = parser.parse_args()
    repository = json.loads((ROOT / "repository.json").read_text())
    manifests = sorted((ROOT / "apps").glob("*.json"))
    if args.app:
        manifests = [path for path in manifests if path.stem == args.app]
    if not manifests:
        parser.error("No matching app manifests")
    for manifest in manifests:
        app = load_app(manifest)
        if manifest.stem != app["name"]:
            raise ValueError("Manifest filename must match its package name")
        if args.check:
            print(f"The manifest for {app['name']} {app['version']}-{app['revision']} is valid.")
            continue
        for architecture, asset in app["assets"].items():
            if args.arch and architecture != args.arch:
                continue
            if architecture not in repository["architectures"]:
                raise ValueError(f"Architecture not enabled: {architecture}")
            version = f"{app['version']}-{app['revision']}"
            arch_output = ROOT / "dist/packages" / f"arch-{architecture}"
            deb_output = ROOT / "dist/packages/apt"
            arch_path = arch_output / f"{app['name']}-{version}-{architecture}.pkg.tar.zst"
            deb_path = deb_output / f"{app['name']}_{version}_{ARCHITECTURES[architecture][0]}.deb"
            want_arch = args.format in ("arch", "all") and not arch_path.exists()
            want_deb = args.format in ("deb", "all") and not deb_path.exists()
            if not (want_arch or want_deb):
                print(f"Reusing the existing {architecture} packages for {app['name']}.")
                continue
            archive = download(asset, ROOT / ".cache/appimages")
            with tempfile.TemporaryDirectory(prefix="yuzu-package-") as directory:
                work = Path(directory)
                root = stage(app, architecture, archive, work)
                if want_arch:
                    build_arch(app, architecture, root, work,
                               arch_output, repository["maintainer"])
                if want_deb:
                    build_deb(app, architecture, root, deb_output, repository["maintainer"])


if __name__ == "__main__":
    main()
