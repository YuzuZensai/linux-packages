# Yuzu's Linux packages

Arch Linux and Debian/Ubuntu repositories for x86_64 and ARM64.

Key fingerprint: `F56FD5C10FCB2570ACBCF8BD916E493E86CC7BF1`

Check that the downloaded key matches this fingerprint before importing it.

## Arch Linux

```sh
curl -fL https://github.com/YuzuZensai/linux-packages/releases/download/arch-x86_64/yuzu.asc -o yuzu.asc
gpg --show-keys --with-fingerprint yuzu.asc
```

```sh
sudo pacman-key --add yuzu.asc
sudo pacman-key --lsign-key F56FD5C10FCB2570ACBCF8BD916E493E86CC7BF1
```

Add to `/etc/pacman.conf`:

```ini
[yuzu]
SigLevel = Required
Server = https://github.com/YuzuZensai/linux-packages/releases/download/arch-$arch
```

```sh
sudo pacman -Syu
```

## Debian / Ubuntu

```sh
curl -fL https://github.com/YuzuZensai/linux-packages/releases/download/apt/yuzu.asc -o yuzu.asc
gpg --show-keys --with-fingerprint yuzu.asc
```

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 yuzu.asc /etc/apt/keyrings/yuzu.asc
sudo tee /etc/apt/sources.list.d/yuzu.sources >/dev/null <<'SOURCE'
Types: deb
URIs: https://github.com/YuzuZensai/linux-packages/releases/download/apt/
Suites: ./
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/yuzu.asc
SOURCE
sudo apt update
```

# License

[0BSD](LICENSE)
