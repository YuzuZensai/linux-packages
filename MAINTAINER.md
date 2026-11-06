# Maintainer guide

Requires Python 3, GPG, GitHub CLI, Docker, and packaging tools. Run as a regular
user with Docker access.

Ubuntu 24.04:

```sh
sudo apt-get install makepkg pacman-package-manager fakeroot zstd squashfs-tools dpkg-dev libarchive-tools desktop-file-utils
```

Arch Linux:

```sh
sudo pacman -Syu --needed fakeroot zstd squashfs-tools dpkg libarchive desktop-file-utils
```

## Publish

```sh
gh auth login
export GPG_TTY="$(tty)"
python3 scripts/release.py --publish
```

Omit `--publish` to build and sign without uploading.

## Update packages

Update the version, URLs, and SHA-256 hashes in `apps/`, then set `revision` to `1`.
For packaging changes to the same version, increase `revision` instead. Publish again.

Republish before APT metadata expires after 30 days, even if no packages changed.

## Checks

```sh
python3 scripts/build.py --check
python3 -m unittest discover -s tests -v
```
