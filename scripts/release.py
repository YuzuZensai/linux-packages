#!/usr/bin/env python3
"""Build, sign locally with GPG, and optionally publish Linux repositories."""

import argparse
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from build import ARCHITECTURES, ROOT, digest, load_app, package_identity, run, write_file


def signing_keys():
    listing = run("gpg", "--batch", "--with-colons", "--fixed-list-mode", "--with-fingerprint",
                  "--list-secret-keys", capture_output=True, text=True).stdout
    keys = []
    primary = None
    now = datetime.now(timezone.utc).timestamp()

    for line in listing.splitlines():
        fields = line.split(":")
        fields += [""] * max(0, 15 - len(fields))
        kind = fields[0]
        valid = fields[1] not in ("r", "e", "d", "i") and "D" not in fields[11]
        if fields[6].isdigit() and int(fields[6]) > 0:
            valid = valid and int(fields[6]) > now

        if kind == "sec":
            primary = {"fingerprint": "", "name": "", "valid": valid, "signing": False}
            keys.append(primary)
        if primary is None:
            continue

        if kind in ("sec", "ssb") and valid and "s" in fields[11] and fields[14] != "#":
            primary["signing"] = True
        elif kind == "fpr" and not primary["fingerprint"]:
            primary["fingerprint"] = fields[9].upper()
        elif kind == "uid" and valid and not primary["name"]:
            name = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda match: bytes([int(match[1], 16)]),
                          fields[9].encode()).decode("utf-8", errors="replace")
            primary["name"] = "".join(char if char.isprintable() else " " for char in name)

    return [key for key in keys if key["valid"] and key["signing"]
            and re.fullmatch(r"[A-F0-9]{40}", key["fingerprint"])]


def select_key(keys):
    if not keys:
        raise ValueError("No usable GPG signing keys found. Create one with gpg --full-generate-key.")
    if not sys.stdin.isatty():
        raise ValueError("Run in a terminal to choose a key, or pass --key FINGERPRINT.")

    print("Choose a GPG key to sign the repository:")
    for index, key in enumerate(keys, 1):
        print(f"  {index}. {key['name'] or 'Unnamed key'}\n     {key['fingerprint']}")

    while True:
        answer = input(f"Signing key (1-{len(keys)}, q to cancel): ").strip()
        if answer.lower() == "q":
            raise KeyboardInterrupt
        if answer.isdecimal() and 1 <= int(answer) <= len(keys):
            return keys[int(answer) - 1]["fingerprint"]
        print(f"Enter a number from 1 to {len(keys)}, or q to cancel.")


class Signer:
    def __init__(self, fingerprint, home=None):
        if not re.fullmatch(r"[A-Fa-f0-9]{40}", fingerprint):
            raise ValueError("Use the full 40-character signing-key fingerprint")
        self.fingerprint = fingerprint.upper()
        self.environment = dict(os.environ)
        if home is not None:
            home.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.environment["GNUPGHOME"] = str(home)

    def gpg(self, *args, secret=False):
        command = ["gpg", "--yes"]
        if not secret:
            command.append("--batch")
        return run(*command, *args, env=self.environment, capture_output=True)

    def sign(self, path, clear=False, armor=False):
        target = path.parent / "InRelease" if clear else Path(str(path) + ".sig")
        self.gpg(*(["--armor"] if armor else []), "--local-user", self.fingerprint, "--output", target,
                 "--clearsign" if clear else "--detach-sign", path, secret=True)
        self.verify(target, None if clear else path)
        return target

    def verify(self, signature, path=None):
        status = self.gpg("--status-fd", "1", "--verify", signature,
                          *([] if path is None else [path])).stdout.decode()
        valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        if not any(self.fingerprint in (line[2], line[-1]) for line in valid):
            raise ValueError("Signature does not match the selected signing key")

    def export(self, directory):
        public = self.gpg("--armor", "--export", self.fingerprint).stdout
        if not public:
            raise ValueError("No public key exported")
        (directory / "yuzu.asc").write_bytes(public)
        write_file(directory / "key.fingerprint", self.fingerprint + "\n")


def create_apt(directory, config, signer, now=None):
    packages = sorted(directory.glob("*.deb"))
    if not packages:
        raise ValueError("Cannot publish an empty APT repository")
    stanzas = []
    architectures = set()
    for package in packages:
        control = run("dpkg-deb", "--field", package, capture_output=True, text=True).stdout.rstrip()
        architecture = run("dpkg-deb", "--field", package, "Architecture",
                           capture_output=True, text=True).stdout.strip()
        architectures.add(architecture)
        stanzas.append(control + f"\nFilename: {package.name}\nSize: {package.stat().st_size}\n"
                       f"SHA256: {digest(package)}\n")
    contents = ("\n".join(stanzas) + "\n").encode()
    (directory / "Packages").write_bytes(contents)
    (directory / "Packages.gz").write_bytes(gzip.compress(contents, mtime=0))
    now = now or datetime.now(timezone.utc)
    release = (
        f"Origin: {config['name']}\nLabel: {config['label']}\nSuite: stable\nCodename: stable\n"
        f"Date: {format_datetime(now, usegmt=True)}\n"
        f"Valid-Until: {format_datetime(now + timedelta(days=30), usegmt=True)}\n"
        f"Architectures: {' '.join(sorted(architectures))}\n"
        f"Description: {config['label']}\n"
    )
    for algorithm, label in (("sha256", "SHA256"), ("sha512", "SHA512")):
        release += label + ":\n"
        for name in ("Packages", "Packages.gz"):
            data = (directory / name).read_bytes()
            checksum = hashlib.new(algorithm, data).hexdigest()
            release += f" {checksum} {len(data):16d} {name}\n"
    path = directory / "Release"
    write_file(path, release)
    if signer:
        signer.sign(path, armor=True).rename(directory / "Release.gpg")
        signer.sign(path, clear=True)


def create_arch(directory, config, signer):
    packages = sorted(directory.glob("*.pkg.tar.zst"))
    if not packages:
        raise ValueError("Cannot publish an empty Arch repository")
    if signer:
        for package in packages:
            signer.sign(package)
    database = directory / (config["name"] + ".db.tar.gz")
    run("repo-add", database, *packages, stdout=subprocess.DEVNULL)

    for suffix in ("db", "files"):
        alias = directory / f"{config['name']}.{suffix}"
        archive = directory / f"{config['name']}.{suffix}.tar.gz"
        if alias.is_symlink():
            alias.unlink()
        shutil.copyfile(archive, alias)
        if signer:
            signer.sign(archive)
            signer.sign(alias)


def assemble(source, destination, config, apps, signer):
    if destination.exists():
        shutil.rmtree(destination)
    expected = {"apt": []}
    identities = {}
    for app in apps:
        for arch in app["assets"]:
            if arch not in config["architectures"]:
                raise ValueError(f"Architecture not enabled: {arch}")
            version = f"{app['version']}-{app['revision']}"
            deb_name = f"{app['name']}_{version}_{ARCHITECTURES[arch][0]}.deb"
            arch_name = f"{app['name']}-{version}-{arch}.pkg.tar.zst"
            expected["apt"].append(deb_name)
            expected.setdefault(f"arch-{arch}", []).append(arch_name)
            identities[deb_name] = identities[arch_name] = package_identity(app, config)
    for channel, names in expected.items():
        directory = destination / channel
        directory.mkdir(parents=True)
        for name in names:
            shutil.copyfile(source / channel / name, directory / name)
        if channel == "apt":
            create_apt(directory, config, signer)
        else:
            create_arch(directory, config, signer)
        if signer:
            signer.export(directory)
        metadata = {"signed": signer is not None, "channel": channel,
                    "fingerprint": signer.fingerprint if signer else None,
                    "sources": {name: identities[name] for name in names},
                    "files": {p.name: digest(p) for p in sorted(directory.iterdir()) if p.is_file()}}
        write_file(directory / "manifest.json", json.dumps(metadata, indent=2) + "\n")
        if signer:
            signer.sign(directory / "manifest.json")


def validate(directory, fingerprint):
    manifest = json.loads((directory / "manifest.json").read_text())
    if not manifest["signed"] or not manifest["fingerprint"]:
        raise ValueError("Refusing to publish unsigned repository metadata")
    fingerprint = fingerprint.upper()
    if manifest["fingerprint"] != fingerprint:
        raise ValueError("The repository does not match the selected signing key")
    with tempfile.TemporaryDirectory(prefix="yuzu-verify-") as temporary:
        verifier = Signer(fingerprint, Path(temporary))
        verifier.gpg("--import", directory / "yuzu.asc")
        verifier.verify(directory / "manifest.json.sig", directory / "manifest.json")
    actual = {p.name for p in directory.iterdir() if p.is_file()} - {"manifest.json", "manifest.json.sig"}
    if actual != set(manifest["files"]):
        raise ValueError("Repository files do not match their manifest")
    for name, checksum in manifest["files"].items():
        if digest(directory / name) != checksum:
            raise ValueError(f"Repository file changed after signing: {name}")
    required = {"yuzu.asc", "key.fingerprint"}
    if directory.name == "apt":
        required |= {"Packages", "Packages.gz", "Release", "Release.gpg", "InRelease"}
    else:
        config = json.loads((ROOT / "repository.json").read_text())
        required |= {config["name"] + ".db", config["name"] + ".db.sig"}
        required |= {p.name + ".sig" for p in directory.glob("*.pkg.tar.zst")}
    if not required <= actual:
        raise ValueError("Missing required signed repository files")
    return manifest


def publish(directory, repository, fingerprint):
    manifest = validate(directory, fingerprint)
    channel = directory.name
    result = subprocess.run(["gh", "api", f"repos/{repository}/releases/tags/{channel}"],
                            capture_output=True, text=True)
    new = result.returncode != 0
    if new:

        if "404" not in result.stderr:
            raise RuntimeError(result.stderr)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md") as notes:
            notes.write("Signed Linux package repository. This release is updated in place.\n"
                        "See the repository README for installation instructions.\n")
            notes.flush()
            run("gh", "release", "create", channel, "--repo", repository, "--draft",
                "--title", f"Yuzu packages: {channel}", "--notes-file", notes.name, "--latest=false")
        release = json.loads(run("gh", "api", f"repos/{repository}/releases/tags/{channel}",
                                 capture_output=True, text=True).stdout)
    else:
        release = json.loads(result.stdout)
    if release.get("immutable"):
        raise ValueError(
            "The repository release cannot be updated because release immutability is enabled. "
            "Disable it before publishing."
        )
    remote = {asset["name"]: asset for asset in release["assets"]}
    packages = [p for p in sorted(directory.iterdir()) if p.name.endswith((".deb", ".pkg.tar.zst"))]
    if release["draft"] and not {"manifest.json", "manifest.json.sig"} <= remote.keys():


        if any(p.name in remote for p in packages):
            raise ValueError(
                "The draft release contains packages without a signed manifest. "
                "Delete the draft release and try again."
            )
        for name in ("manifest.json", "manifest.json.sig"):
            run("gh", "release", "upload", channel, directory / name, "--repo", repository, "--clobber")

    for package in packages:
        if package.name in remote:
            checksum = remote[package.name].get("digest")
            if not checksum:
                with tempfile.TemporaryDirectory(prefix="yuzu-remote-") as temporary:
                    run("gh", "release", "download", channel, "--repo", repository,
                        "--pattern", package.name, "--dir", temporary)
                    checksum = "sha256:" + digest(Path(temporary) / package.name)
            if checksum != "sha256:" + digest(package):
                raise ValueError(
                    f"{package.name} is already published with different contents. "
                    "Increase the package revision before publishing again."
                )
        else:
            run("gh", "release", "upload", channel, package, "--repo", repository)


    metadata = sorted((p for p in directory.iterdir() if p not in packages),
                      key=lambda p: (p.name == "InRelease", p.name == "Release.gpg", p.name))
    for path in metadata:
        run("gh", "release", "upload", channel, path, "--repo", repository, "--clobber")
    if new or release["draft"]:
        run("gh", "release", "edit", channel, "--repo", repository, "--draft=false", "--latest=false")
    print(f"Published the {channel} repository, signed with key {manifest['fingerprint']}.")


def restore(config, apps, signer):
    wanted = {"apt": {}}
    for app in apps:
        for arch in app["assets"]:
            version = f"{app['version']}-{app['revision']}"
            wanted["apt"][f"{app['name']}_{version}_{ARCHITECTURES[arch][0]}.deb"] = package_identity(app, config)
            wanted.setdefault(f"arch-{arch}", {})[f"{app['name']}-{version}-{arch}.pkg.tar.zst"] = package_identity(app, config)
    for channel, names in wanted.items():
        response = subprocess.run(["gh", "api", f"repos/{config['github']}/releases/tags/{channel}"],
                                  capture_output=True, text=True)
        if response.returncode:
            if "404" in response.stderr:
                continue
            raise RuntimeError(response.stderr)
        release = json.loads(response.stdout)
        remote_names = {asset["name"] for asset in release.get("assets", [])}
        if release["draft"] and not {"manifest.json", "manifest.json.sig"} <= remote_names:

            continue
        with tempfile.TemporaryDirectory(prefix="yuzu-restore-") as temporary:
            folder = Path(temporary)
            for name in ("manifest.json", "manifest.json.sig"):
                run("gh", "release", "download", channel, "--repo", config["github"],
                    "--pattern", name, "--dir", folder)
            signer.verify(folder / "manifest.json.sig", folder / "manifest.json")
            manifest = json.loads((folder / "manifest.json").read_text())
            if manifest["channel"] != channel or manifest["fingerprint"] != signer.fingerprint:
                raise ValueError("Published channel has an unexpected signing identity")
            for name, identity in names.items():
                if name not in manifest["sources"]:
                    continue
                if manifest["sources"][name] != identity:
                    raise ValueError(
                        f"The build inputs for {name} have changed. "
                        "Increase the package revision before rebuilding."
                    )
                if release["draft"] and name not in remote_names:
                    continue
                target = ROOT / "dist/packages" / channel
                target.mkdir(parents=True, exist_ok=True)
                run("gh", "release", "download", channel, "--repo", config["github"],
                    "--pattern", name, "--dir", target)
                if digest(target / name) != manifest["files"][name]:
                    raise ValueError(f"Published package checksum mismatch: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", help="Use this signing key. Omit this option to choose from your local keys.")
    parser.add_argument("--publish", action="store_true", help="Check installation and upload signed repositories")
    args = parser.parse_args()
    config = json.loads((ROOT / "repository.json").read_text())
    apps = [load_app(path) for path in sorted((ROOT / "apps").glob("*.json"))]
    try:
        signer = Signer(args.key or select_key(signing_keys()))
        signer.gpg("--list-secret-keys", signer.fingerprint)
    except ValueError as error:
        parser.error(str(error))
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    shutil.rmtree(ROOT / "dist", ignore_errors=True)
    restore(config, apps, signer)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("SIGNING_") and key not in ("GH_TOKEN", "GITHUB_TOKEN")}
    run(sys.executable, ROOT / "scripts/build.py", env=environment)
    assemble(ROOT / "dist/packages", ROOT / "dist/repositories", config, apps, signer)

    if args.publish:
        run("bash", ROOT / "tests/install-eda.sh")
        directories = sorted((ROOT / "dist/repositories").iterdir())
        for directory in directories:
            validate(directory, signer.fingerprint)
        for directory in directories:
            publish(directory, config["github"], signer.fingerprint)


if __name__ == "__main__":
    main()
